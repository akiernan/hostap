/*
 * WPA Supplicant - background scan and roaming module: quiet
 * Copyright (c) 2026, Alex Kiernan <alex.kiernan@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * A background scan module that never scans while the link is good. While the
 * signal is below the threshold it scans for a better BSS in the same ESS,
 * doubling the interval after each of its own scans up to a maximum. Roaming
 * is left to the normal BSS selection on the scan results.
 *
 * Configuration: bgscan="quiet:<short interval>:<threshold>:<max interval>"
 *
 * Signal state comes from the driver's signal change events where the driver
 * sends them. Until the first such event arrives, the signal is polled and
 * the same threshold and hysteresis are applied here.
 */

#include "includes.h"
#include <limits.h>

#include "common.h"
#include "eloop.h"
#include "drivers/driver.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "bgscan.h"

#define BGSCAN_QUIET_HYSTERESIS 4
#define BGSCAN_QUIET_POLL_INTERVAL 10

struct bgscan_quiet_data {
	struct wpa_supplicant *wpa_s;
	const struct wpa_ssid *ssid;
	int short_interval;
	int signal_threshold;
	int max_interval;

	bool weak;
	int scan_interval; /* next interval while weak */
	bool had_weak_spell;
	struct os_reltime good_since;

	bool monitor; /* driver accepted signal monitoring */
	bool events_seen; /* driver has sent a signal change event */
	int last_signal; /* signal at the last state change, 0 if unknown */
};


static void bgscan_quiet_timeout(void *eloop_ctx, void *timeout_ctx);
static void bgscan_quiet_poll(void *eloop_ctx, void *timeout_ctx);


static void bgscan_quiet_schedule(struct bgscan_quiet_data *data, int secs)
{
	eloop_cancel_timeout(bgscan_quiet_timeout, data, NULL);
	eloop_register_timeout(secs, 0, bgscan_quiet_timeout, data, NULL);
}


static void bgscan_quiet_set_weak(struct bgscan_quiet_data *data, int signal)
{
	struct os_reltime now;

	data->last_signal = signal;
	if (data->weak)
		return;

	data->weak = true;
	os_get_reltime(&now);
	if (!data->had_weak_spell ||
	    os_reltime_expired(&now, &data->good_since, data->max_interval))
		data->scan_interval = data->short_interval;
	wpa_printf(MSG_DEBUG,
		   "bgscan quiet: Signal weak (%d dBm), scan in %d s",
		   signal, data->scan_interval);
	bgscan_quiet_schedule(data, data->scan_interval);
}


static void bgscan_quiet_set_good(struct bgscan_quiet_data *data, int signal)
{
	data->last_signal = signal;
	if (!data->weak)
		return;

	data->weak = false;
	data->had_weak_spell = true;
	os_get_reltime(&data->good_since);
	wpa_printf(MSG_DEBUG, "bgscan quiet: Signal good (%d dBm), stop scanning",
		   signal);
	eloop_cancel_timeout(bgscan_quiet_timeout, data, NULL);
}


/*
 * Apply the threshold to a polled signal the way mac80211 applies it for
 * signal change events: a state change needs the signal to cross the
 * threshold and to have moved by more than the hysteresis since the last
 * state change.
 */
static void bgscan_quiet_signal(struct bgscan_quiet_data *data, int signal)
{
	int last = data->last_signal;

	if (!data->weak && signal < data->signal_threshold &&
	    (last == 0 || signal < last - BGSCAN_QUIET_HYSTERESIS))
		bgscan_quiet_set_weak(data, signal);
	else if (data->weak && signal > data->signal_threshold &&
		 (last == 0 || signal > last + BGSCAN_QUIET_HYSTERESIS))
		bgscan_quiet_set_good(data, signal);
}


static void bgscan_quiet_poll(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_quiet_data *data = eloop_ctx;
	struct wpa_signal_info si;

	if (data->events_seen)
		return;

	if (wpa_drv_signal_poll(data->wpa_s, &si) == 0)
		bgscan_quiet_signal(data, si.data.signal);

	eloop_register_timeout(BGSCAN_QUIET_POLL_INTERVAL, 0,
			       bgscan_quiet_poll, data, NULL);
}


static void bgscan_quiet_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_quiet_data *data = eloop_ctx;
	struct wpa_supplicant *wpa_s = data->wpa_s;
	struct wpa_driver_scan_params params;

	if (!data->weak)
		return;

	os_memset(&params, 0, sizeof(params));
	params.num_ssids = 1;
	params.ssids[0].ssid = data->ssid->ssid;
	params.ssids[0].ssid_len = data->ssid->ssid_len;
	params.freqs = data->ssid->scan_freq;

	wpa_printf(MSG_DEBUG, "bgscan quiet: Request a background scan");
	if (wpa_supplicant_trigger_scan(wpa_s, &params, true, false)) {
		wpa_printf(MSG_DEBUG, "bgscan quiet: Failed to trigger scan");
	} else if (data->scan_interval > data->max_interval / 2) {
		data->scan_interval = data->max_interval;
	} else {
		data->scan_interval *= 2;
	}

	/*
	 * The scan results restart this timer; this covers a scan that never
	 * completes.
	 */
	bgscan_quiet_schedule(data, data->scan_interval);
}


static int bgscan_quiet_get_int(const char **pos, int *val)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(*pos, &end, 10);
	if (end == *pos || errno || v < INT_MIN || v > INT_MAX)
		return -1;
	*val = v;
	*pos = end;
	return 0;
}


static int bgscan_quiet_get_params(struct bgscan_quiet_data *data,
				   const char *params)
{
	const char *pos = params;

	if (bgscan_quiet_get_int(&pos, &data->short_interval) < 0 ||
	    *pos++ != ':' ||
	    bgscan_quiet_get_int(&pos, &data->signal_threshold) < 0 ||
	    *pos++ != ':' ||
	    bgscan_quiet_get_int(&pos, &data->max_interval) < 0 ||
	    *pos != '\0') {
		wpa_printf(MSG_ERROR,
			   "bgscan quiet: Invalid parameters '%s', expected <short interval>:<threshold>:<max interval>",
			   params);
		return -1;
	}

	if (data->short_interval <= 0 || data->max_interval <= 0 ||
	    data->short_interval > data->max_interval) {
		wpa_printf(MSG_ERROR,
			   "bgscan quiet: Need 0 < short interval (%d) <= max interval (%d)",
			   data->short_interval, data->max_interval);
		return -1;
	}

	if (data->signal_threshold >= 0) {
		wpa_printf(MSG_ERROR,
			   "bgscan quiet: Signal threshold (%d) must be below 0 dBm",
			   data->signal_threshold);
		return -1;
	}

	return 0;
}


static void * bgscan_quiet_init(struct wpa_supplicant *wpa_s,
				const char *params,
				const struct wpa_ssid *ssid)
{
	struct bgscan_quiet_data *data;
	struct wpa_signal_info si;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;
	data->wpa_s = wpa_s;
	data->ssid = ssid;
	if (bgscan_quiet_get_params(data, params) < 0) {
		os_free(data);
		return NULL;
	}

	wpa_printf(MSG_DEBUG,
		   "bgscan quiet: Signal threshold %d  Short interval %d  Max interval %d",
		   data->signal_threshold, data->short_interval,
		   data->max_interval);

	if (wpa_drv_signal_monitor(wpa_s, data->signal_threshold,
				   BGSCAN_QUIET_HYSTERESIS) == 0)
		data->monitor = true;
	else
		wpa_printf(MSG_DEBUG,
			   "bgscan quiet: Driver signal monitoring not available");
	wpa_s->signal_threshold = data->signal_threshold;

	data->scan_interval = data->short_interval;
	if (wpa_drv_signal_poll(wpa_s, &si) < 0) {
		wpa_printf(MSG_DEBUG,
			   "bgscan quiet: Signal unknown, assuming weak");
		bgscan_quiet_set_weak(data, 0);
	} else if (si.data.signal < data->signal_threshold) {
		bgscan_quiet_set_weak(data, si.data.signal);
	} else {
		data->last_signal = si.data.signal;
		wpa_printf(MSG_DEBUG, "bgscan quiet: Signal good (%d dBm)",
			   si.data.signal);
	}

	/*
	 * Poll until the driver shows it sends signal change events; a driver
	 * can accept the signal monitor configuration and never report.
	 */
	eloop_register_timeout(BGSCAN_QUIET_POLL_INTERVAL, 0,
			       bgscan_quiet_poll, data, NULL);

	return data;
}


static void bgscan_quiet_deinit(void *priv)
{
	struct bgscan_quiet_data *data = priv;

	eloop_cancel_timeout(bgscan_quiet_timeout, data, NULL);
	eloop_cancel_timeout(bgscan_quiet_poll, data, NULL);
	data->wpa_s->signal_threshold = 0;
	if (data->monitor)
		wpa_drv_signal_monitor(data->wpa_s, 0, 0);
	os_free(data);
}


static int bgscan_quiet_notify_scan(void *priv,
				    struct wpa_scan_results *scan_res)
{
	struct bgscan_quiet_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan quiet: Scan result notification");

	/*
	 * Fresh results from any scan push the next one back a full interval.
	 * The interval only grows when this module requests the scan.
	 */
	if (data->weak)
		bgscan_quiet_schedule(data, data->scan_interval);

	/* Leave BSS selection and roaming to the normal path */
	return 0;
}


static void bgscan_quiet_notify_beacon_loss(void *priv)
{
	struct bgscan_quiet_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan quiet: Beacon loss");

	/* Treat as a fresh drop below the threshold */
	bgscan_quiet_set_weak(data, 0);

	/*
	 * The driver reports only changes, so if the signal is in fact good it
	 * would not report it again. Restart its monitoring so it reports the
	 * current level afresh.
	 */
	if (data->monitor && data->events_seen) {
		wpa_drv_signal_monitor(data->wpa_s, 0, 0);
		if (wpa_drv_signal_monitor(data->wpa_s, data->signal_threshold,
					   BGSCAN_QUIET_HYSTERESIS) < 0) {
			wpa_printf(MSG_DEBUG,
				   "bgscan quiet: Failed to restart signal monitoring, polling");
			data->monitor = false;
			data->events_seen = false;
			eloop_cancel_timeout(bgscan_quiet_poll, data, NULL);
			eloop_register_timeout(BGSCAN_QUIET_POLL_INTERVAL, 0,
					       bgscan_quiet_poll, data, NULL);
		}
	}
}


static void bgscan_quiet_notify_signal_change(void *priv, int above,
					      int current_signal,
					      int current_noise,
					      int current_txrate)
{
	struct bgscan_quiet_data *data = priv;

	wpa_printf(MSG_DEBUG,
		   "bgscan quiet: Signal change (above=%d signal=%d)",
		   above, current_signal);

	if (!data->events_seen) {
		data->events_seen = true;
		eloop_cancel_timeout(bgscan_quiet_poll, data, NULL);
	}

	if (above)
		bgscan_quiet_set_good(data, current_signal);
	else
		bgscan_quiet_set_weak(data, current_signal);
}


const struct bgscan_ops bgscan_quiet_ops = {
	.name = "quiet",
	.init = bgscan_quiet_init,
	.deinit = bgscan_quiet_deinit,
	.notify_scan = bgscan_quiet_notify_scan,
	.notify_beacon_loss = bgscan_quiet_notify_beacon_loss,
	.notify_signal_change = bgscan_quiet_notify_signal_change,
};
