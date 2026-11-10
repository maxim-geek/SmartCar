#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

#include "esphome/core/application.h"
#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "esphome/core/preferences.h"
#include "esphome/components/logger/logger.h"
#include "esphome/components/ota/ota_backend_esp_idf.h"
#include "esphome/components/wifi/scan_list.h"
#include "esphome/components/wifi/wifi_component.h"

#include <driver/ledc.h>
#include <esp_https_server.h>
#include <esp_netif.h>
#include <esp_system.h>
#include <esp_wifi.h>

namespace esphome {
namespace remote_https {

static const char *const TAG = "remote_https";

/// Everything the setup page can change; stored in flash (survives reboots and re-flashing).
struct Settings {
  uint32_t magic;
  uint8_t pins[4];     // drive forward, drive reverse, steer right, steer left
  uint8_t steer_mode;  // 0 = on/off, 1 = proportional
  uint8_t steer_thr;   // percent, on/off steering engages past this
  uint8_t tilt_dz;     // degrees
  uint8_t tilt_rg;     // degrees for full speed
  uint8_t reserved0;  // unused (was: invert throttle)
  uint8_t reserved1;  // unused (was: invert steering)
  uint8_t accel;  // tenths of a second from 0 to full speed (2..50)
  uint8_t brake;  // tenths of a second from full speed to stop (0..20)
  uint8_t kick;   // tenths of a second of full steering power (2..50)
  uint8_t hold;   // percent of power that holds the steering position (10..100)
};
static constexpr uint32_t SETTINGS_MAGIC = 0x52433034;
static constexpr int LOG_LINES = 64;
static constexpr int LOG_TEXT = 128;

/// Serves the remote page and a setup page (Wi-Fi, tilt, pins, OTA, log) over HTTPS with a
/// self-signed certificate, and drives the two motors directly with ESP-IDF LEDC.
/// HTTP handlers only record requests; outputs and flash writes run from loop().
class RemoteHttps : public Component {
 public:
  void set_html(const char *v) { this->html_ = v; }
  void set_config_html(const char *v) { this->config_html_ = v; }
  void set_config_auth(const char *v) { this->auth_header_ = v; }
  void set_cert(const char *v) { this->cert_ = v; }
  void set_key(const char *v) { this->key_ = v; }
  void set_port(uint16_t v) { this->port_ = v; }
  void set_failsafe_ms(uint32_t v) { this->failsafe_ms_ = v; }
  void set_http_redirect(bool v) { this->http_redirect_ = v; }
  void set_default_pins(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    this->defaults_.pins[0] = a;
    this->defaults_.pins[1] = b;
    this->defaults_.pins[2] = c;
    this->defaults_.pins[3] = d;
  }
  void set_default_steer(bool proportional, uint8_t threshold_percent) {
    this->defaults_.steer_mode = proportional ? 1 : 0;
    this->defaults_.steer_thr = threshold_percent;
  }
  void set_default_tilt(uint8_t deadzone, uint8_t range) {
    this->defaults_.tilt_dz = deadzone;
    this->defaults_.tilt_rg = range;
  }
  void set_default_motion(uint8_t accel, uint8_t brake, uint8_t kick, uint8_t hold) {
    this->defaults_.accel = accel;
    this->defaults_.brake = brake;
    this->defaults_.kick = kick;
    this->defaults_.hold = hold;
  }

  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void setup() override {
    // Log capture for the debug page (register first so boot messages are kept).
    if (logger::global_logger != nullptr)
      logger::global_logger->add_log_callback(this, &RemoteHttps::log_cb_);

    // Settings: flash copy if valid, otherwise the YAML defaults.
    this->defaults_.magic = SETTINGS_MAGIC;
    this->pref_ = global_preferences->make_preference<Settings>(0x52435345UL, true);
    Settings loaded{};
    if (this->pref_.load(&loaded) && this->valid_(loaded)) {
      this->settings_ = loaded;
    } else {
      this->settings_ = this->defaults_;
    }
    this->load_motion_();

    this->setup_motors_();
    this->last_update_ = millis();
    this->update_motors_(this->last_update_);

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.port_secure = this->port_;
    conf.httpd.ctrl_port = 32769;  // avoid clashing with ESPHome's own HTTP server
    conf.httpd.lru_purge_enable = true;
    conf.httpd.max_uri_handlers = 24;
    conf.httpd.stack_size = 12288;
    conf.servercert = reinterpret_cast<const uint8_t *>(this->cert_);
    conf.servercert_len = strlen(this->cert_) + 1;
    conf.prvtkey_pem = reinterpret_cast<const uint8_t *>(this->key_);
    conf.prvtkey_len = strlen(this->key_) + 1;

    esp_err_t err = httpd_ssl_start(&this->server_, &conf);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "httpd_ssl_start failed: %s", esp_err_to_name(err));
      this->mark_failed();
      return;
    }
    this->register_("/", HTTP_GET, &RemoteHttps::page_handler_);
    this->register_("/c", HTTP_GET, &RemoteHttps::cmd_handler_);
    this->register_("/tilt", HTTP_GET, &RemoteHttps::tilt_handler_);
    this->register_("/config", HTTP_GET, &RemoteHttps::config_handler_);
    this->register_("/api/settings", HTTP_GET, &RemoteHttps::settings_get_handler_);
    this->register_("/api/settings", HTTP_POST, &RemoteHttps::settings_post_handler_);
    this->register_("/scan", HTTP_GET, &RemoteHttps::scan_handler_);
    this->register_("/networks", HTTP_GET, &RemoteHttps::networks_handler_);
    this->register_("/status", HTTP_GET, &RemoteHttps::status_handler_);
    this->register_("/save", HTTP_POST, &RemoteHttps::save_handler_);
    this->register_("/forget", HTTP_POST, &RemoteHttps::forget_handler_);
    this->register_("/update", HTTP_POST, &RemoteHttps::update_handler_);
    this->register_("/logs", HTTP_GET, &RemoteHttps::logs_handler_);
    this->register_("/reboot", HTTP_POST, &RemoteHttps::reboot_handler_);

    if (this->http_redirect_) {
      // Plain http on port 80: redirect everything to the https page.
      httpd_config_t rc = HTTPD_DEFAULT_CONFIG();
      rc.server_port = 80;
      rc.ctrl_port = 32770;
      rc.max_open_sockets = 3;
      rc.lru_purge_enable = true;
      rc.uri_match_fn = httpd_uri_match_wildcard;
      if (httpd_start(&this->redirect_server_, &rc) == ESP_OK) {
        httpd_uri_t uri = {};
        uri.uri = "/*";
        uri.method = HTTP_GET;
        uri.handler = &RemoteHttps::redirect_handler_;
        uri.user_ctx = this;
        httpd_register_uri_handler(this->redirect_server_, &uri);
      } else {
        ESP_LOGW(TAG, "Could not start http->https redirect on port 80");
      }
    }
    ESP_LOGI(TAG, "Setup page ready: https://<car-address>/config");
  }

  void loop() override {
    // New settings from the setup page: store in flash (main task), maybe restart for pins.
    if (this->pending_settings_.exchange(false)) {
      Settings ns;
      {
        std::lock_guard<std::mutex> g(this->settings_mutex_);
        ns = this->pending_;
      }
      bool pins_changed = memcmp(ns.pins, this->settings_.pins, sizeof(ns.pins)) != 0;
      {
        std::lock_guard<std::mutex> g(this->settings_mutex_);
        this->settings_ = ns;
      }
      this->load_motion_();
      this->pref_.save(&this->settings_);
      global_preferences->sync();
      ESP_LOGI(TAG, "Settings saved%s", pins_changed ? ", restarting for new pins" : "");
      if (pins_changed)
        this->schedule_reboot_(1500);
    }

    // Wi-Fi credentials from the setup page.
    if (this->pending_wifi_.exchange(false)) {
      ESP_LOGI(TAG, "Saving Wi-Fi network '%s' and restarting", this->pending_ssid_);
      this->target_t_ = 0;
      this->target_s_ = 0;
      wifi::global_wifi_component->save_wifi_sta(this->pending_ssid_, this->pending_psk_);
      this->schedule_reboot_(1500);
    }

    if (this->reboot_pending_.load() && (int32_t)(millis() - this->reboot_at_.load()) >= 0) {
      this->reboot_pending_ = false;
      App.safe_reboot();
    }

    uint32_t now = millis();
    if ((this->target_t_.load() != 0 || this->target_s_.load() != 0) &&
        (now - this->last_cmd_.load()) > this->failsafe_ms_) {
      // No commands any more (page closed, Wi-Fi lost): stop at once, no braking ramp.
      ESP_LOGW(TAG, "No command for %u ms: stopping the car", (unsigned) (now - this->last_cmd_.load()));
      this->ramp_ = false;
      this->target_t_ = 0;
      this->target_s_ = 0;
    }
    this->update_motors_(now);
  }

  void dump_config() override {
    ESP_LOGCONFIG(TAG, "Remote HTTPS page on port %u (failsafe %u ms, setup page auth %s)", this->port_,
                  (unsigned) this->failsafe_ms_, this->auth_header_.empty() ? "off" : "on");
    ESP_LOGCONFIG(TAG, "Motor pins: drive %d/%d, steer %d/%d", this->settings_.pins[0], this->settings_.pins[1],
                  this->settings_.pins[2], this->settings_.pins[3]);
  }

 protected:
  struct LogEntry {
    uint32_t seq;
    char text[LOG_TEXT];
  };

  // ---------- pins ----------
  static const uint8_t *allowed_pins_(size_t &count) {
#if defined(CONFIG_IDF_TARGET_ESP32C3)
    static const uint8_t pins[] = {0, 1, 3, 4, 5, 6, 7, 10};
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    static const uint8_t pins[] = {1,  2,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
                                   15, 16, 17, 18, 21, 38, 39, 40, 41, 42, 47, 48};
#elif defined(CONFIG_IDF_TARGET_ESP32)
    static const uint8_t pins[] = {4, 5, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33};
#else
    static const uint8_t pins[] = {4, 5, 6, 7};
#endif
    count = sizeof(pins);
    return pins;
  }

  bool pin_ok_(uint8_t pin) const {
    size_t n = 0;
    const uint8_t *list = allowed_pins_(n);
    for (size_t i = 0; i < n; i++)
      if (list[i] == pin)
        return true;
    for (int i = 0; i < 4; i++)  // pins chosen in the YAML are always accepted
      if (this->defaults_.pins[i] == pin)
        return true;
    return false;
  }

  bool valid_(const Settings &s) const {
    if (s.magic != SETTINGS_MAGIC)
      return false;
    for (int i = 0; i < 4; i++) {
      if (!this->pin_ok_(s.pins[i]))
        return false;
      for (int j = i + 1; j < 4; j++)
        if (s.pins[i] == s.pins[j])
          return false;
    }
    return s.steer_mode <= 1 && s.steer_thr >= 5 && s.steer_thr <= 95 && s.tilt_dz >= 1 && s.tilt_dz <= 30 &&
           s.tilt_rg >= 5 && s.tilt_rg <= 80 && s.tilt_rg > s.tilt_dz &&
           s.accel >= 2 && s.accel <= 50 && s.brake <= 20 && s.kick >= 2 && s.kick <= 50 && s.hold >= 10 &&
           s.hold <= 100;
  }

  // ---------- motors (ESP-IDF LEDC, channels 0..3 on timer 0) ----------
  void setup_motors_() {
    ledc_timer_config_t timer = {};
    timer.speed_mode = LEDC_LOW_SPEED_MODE;
    timer.duty_resolution = LEDC_TIMER_10_BIT;
    timer.timer_num = LEDC_TIMER_0;
    timer.freq_hz = 5000;
    timer.clk_cfg = LEDC_AUTO_CLK;
    ledc_timer_config(&timer);
    for (int i = 0; i < 4; i++) {
      ledc_channel_config_t ch = {};
      ch.gpio_num = this->settings_.pins[i];
      ch.speed_mode = LEDC_LOW_SPEED_MODE;
      ch.channel = static_cast<ledc_channel_t>(i);
      ch.intr_type = LEDC_INTR_DISABLE;
      ch.timer_sel = LEDC_TIMER_0;
      ch.duty = 0;
      ch.hpoint = 0;
      ledc_channel_config(&ch);
    }
  }

  void set_pwm_(int channel, float level) {
    if (level < 0.0f)
      level = 0.0f;
    if (level > 1.0f)
      level = 1.0f;
    uint32_t duty = static_cast<uint32_t>(level * 1023.0f + 0.5f);
    if (duty == this->duty_[channel])
      return;
    this->duty_[channel] = duty;
    ledc_set_duty(LEDC_LOW_SPEED_MODE, static_cast<ledc_channel_t>(channel), duty);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, static_cast<ledc_channel_t>(channel));
  }

  void load_motion_() {
    this->steer_mode_ = this->settings_.steer_mode;
    this->steer_thr_ = this->settings_.steer_thr;
    this->accel_ = this->settings_.accel;
    this->brake_ = this->settings_.brake;
    this->kick_ = this->settings_.kick;
    this->hold_ = this->settings_.hold;
  }

  /// Runs every loop(): ramps the drive motor towards its target and runs the steering
  /// motor with a short full-power "kick" followed by a lower holding power.
  void update_motors_(uint32_t now) {
    float dt = (now - this->last_update_) / 1000.0f;
    this->last_update_ = now;
    if (dt > 0.1f)
      dt = 0.1f;

    // ----- drive motor -----
    float target = static_cast<float>(this->target_t_.load());
    if (!this->ramp_.load()) {
      this->cur_t_ = target;
    } else {
      float up = 100.0f / (this->accel_.load() * 0.1f);  // percent per second
      uint8_t b = this->brake_.load();
      float down = b == 0 ? 1.0e6f : 100.0f / (b * 0.1f);
      bool toward_zero = (this->cur_t_ > 0 && target < this->cur_t_) || (this->cur_t_ < 0 && target > this->cur_t_);
      float step = (toward_zero ? down : up) * dt;
      float diff = target - this->cur_t_;
      if (diff <= step && diff >= -step)
        this->cur_t_ = target;
      else
        this->cur_t_ += diff > 0 ? step : -step;
    }
    float tf = this->cur_t_ / 100.0f;
    this->set_pwm_(0, tf > 0 ? tf : 0.0f);
    this->set_pwm_(1, tf < 0 ? -tf : 0.0f);

    // ----- steering motor -----
    int s = this->target_s_.load();
    float sf = s / 100.0f;
    if (this->steer_mode_.load() == 1) {
      this->steer_dir_ = 0;
      this->set_pwm_(2, sf > 0 ? sf : 0.0f);
      this->set_pwm_(3, sf < 0 ? -sf : 0.0f);
    } else {
      float th = this->steer_thr_.load() / 100.0f;
      int dir = sf > th ? 1 : (sf < -th ? -1 : 0);
      if (dir != this->steer_dir_) {
        this->steer_dir_ = dir;
        this->steer_started_ = now;
        if (dir != 0)
          ESP_LOGI(TAG, "Steering %s: full power for %.1f s, then %u%%", dir > 0 ? "right" : "left",
                   this->kick_.load() / 10.0f, (unsigned) this->hold_.load());
      }
      float level = 0.0f;
      if (dir != 0) {
        uint32_t elapsed = now - this->steer_started_;
        if (elapsed < static_cast<uint32_t>(this->kick_.load()) * 100U) {
          // soft start: 25% -> 100% over 150 ms to soften the current spike of a stalled motor
          level = elapsed < 150U ? 0.25f + 0.75f * (elapsed / 150.0f) : 1.0f;
        } else {
          level = this->hold_.load() / 100.0f;
        }
      }
      this->set_pwm_(2, dir > 0 ? level : 0.0f);
      this->set_pwm_(3, dir < 0 ? level : 0.0f);
    }
  }

  void schedule_reboot_(uint32_t delay_ms) {
    this->ramp_ = false;
    this->target_t_ = 0;
    this->target_s_ = 0;
    this->reboot_at_ = millis() + delay_ms;
    this->reboot_pending_ = true;
  }

  // ---------- log capture ----------
  static void log_cb_(void *instance, uint8_t level, const char *tag, const char *msg, size_t len) {
    static_cast<RemoteHttps *>(instance)->add_log_(level, tag, msg, len);
  }

  void add_log_(uint8_t level, const char *tag, const char *msg, size_t len) {
    static const char LEVELS[] = "NEWICDVV";
    std::lock_guard<std::mutex> g(this->log_mutex_);
    LogEntry &e = this->log_[this->log_seq_ % LOG_LINES];
    e.seq = this->log_seq_++;
    size_t o = 0;
    auto put = [&](char c) {
      if (o + 1 < sizeof(e.text))
        e.text[o++] = c;
    };
    put(level < sizeof(LEVELS) - 1 ? LEVELS[level] : 'I');
    put('[');
    for (const char *p = tag; *p != '\0'; p++)
      put(*p);
    put(']');
    put(' ');
    for (size_t i = 0; i < len; i++) {
      char c = msg[i];
      if (c == 0x1b) {  // skip ANSI colour sequences
        while (i < len && msg[i] != 'm')
          i++;
        continue;
      }
      if (c == '\n' || c == '\r')
        continue;
      if (static_cast<unsigned char>(c) < 0x20)
        c = ' ';
      put(c);
    }
    e.text[o] = '\0';
  }

  void register_(const char *path, httpd_method_t method, esp_err_t (*handler)(httpd_req_t *)) {
    httpd_uri_t uri = {};
    uri.uri = path;
    uri.method = method;
    uri.handler = handler;
    uri.user_ctx = this;
    httpd_register_uri_handler(this->server_, &uri);
  }

  // ---------- helpers ----------
  static void url_decode_(char *dst, size_t dst_len, const char *src) {
    size_t n = 0;
    while (*src != '\0' && n + 1 < dst_len) {
      if (*src == '%' && isxdigit((unsigned char) src[1]) && isxdigit((unsigned char) src[2])) {
        char h[3] = {src[1], src[2], '\0'};
        dst[n++] = static_cast<char>(strtol(h, nullptr, 16));
        src += 3;
      } else if (*src == '+') {
        dst[n++] = ' ';
        src++;
      } else {
        dst[n++] = *src++;
      }
    }
    dst[n] = '\0';
  }

  static void json_escape_(std::string &out, const char *s) {
    for (; *s != '\0'; s++) {
      unsigned char c = static_cast<unsigned char>(*s);
      if (c == '"' || c == '\\') {
        out += '\\';
        out += static_cast<char>(c);
      } else if (c < 0x20) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out += static_cast<char>(c);
      }
    }
  }

  static esp_err_t send_json_(httpd_req_t *req, const std::string &body) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, body.c_str(), body.size());
  }

  static esp_err_t send_text_(httpd_req_t *req, const char *status, const char *text) {
    httpd_resp_set_status(req, status);
    return httpd_resp_send(req, text, HTTPD_RESP_USE_STRLEN);
  }

  /// Reads a small request body (form-encoded). Returns false if it is missing or too large.
  static bool read_body_(httpd_req_t *req, char *buf, size_t cap) {
    size_t total = req->content_len;
    if (total == 0 || total + 1 > cap)
      return false;
    size_t got = 0;
    while (got < total) {
      int r = httpd_req_recv(req, buf + got, total - got);
      if (r == HTTPD_SOCK_ERR_TIMEOUT)
        continue;
      if (r <= 0)
        return false;
      got += static_cast<size_t>(r);
    }
    buf[got] = '\0';
    return true;
  }

  static bool form_int_(const char *body, const char *key, int *out) {
    char v[16];
    if (httpd_query_key_value(body, key, v, sizeof(v)) != ESP_OK)
      return false;
    *out = atoi(v);
    return true;
  }

  /// HTTP Basic auth for the setup endpoints (no-op when no password is configured).
  bool authorized_(httpd_req_t *req) {
    if (this->auth_header_.empty())
      return true;
    size_t len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (len > 0 && len < 200) {
      char buf[200];
      if (httpd_req_get_hdr_value_str(req, "Authorization", buf, sizeof(buf)) == ESP_OK &&
          this->auth_header_ == buf)
        return true;
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"SmartCar\"");
    httpd_resp_send(req, "Unauthorized", HTTPD_RESP_USE_STRLEN);
    return false;
  }

  // ---------- remote control page ----------
  static esp_err_t page_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, self->html_, HTTPD_RESP_USE_STRLEN);
  }

  // Any plain-http request -> 302 to https://<same host>/
  static esp_err_t redirect_handler_(httpd_req_t *req) {
    char host[64] = {0};
    httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host));
    char *colon = strchr(host, ':');
    if (colon != nullptr && host[0] != '[')
      *colon = '\0';
    char loc[96];
    snprintf(loc, sizeof(loc), "https://%s/", host);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", loc);
    return httpd_resp_send(req, nullptr, 0);
  }

  // GET /c?t=<-100..100>&s=<-100..100>  (also acts as keep-alive)
  static esp_err_t cmd_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    char query[64];
    char val[16];
    if (!self->ota_active_.load() && httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
      int t = 0, s = 0;
      if (httpd_query_key_value(query, "t", val, sizeof(val)) == ESP_OK)
        t = atoi(val);
      if (httpd_query_key_value(query, "s", val, sizeof(val)) == ESP_OK)
        s = atoi(val);
      self->ramp_ = httpd_query_key_value(query, "r", val, sizeof(val)) == ESP_OK && atoi(val) != 0;
      self->target_t_ = t < -100 ? -100 : (t > 100 ? 100 : t);
      self->target_s_ = s < -100 ? -100 : (s > 100 ? 100 : s);
      self->last_cmd_ = millis();
    }
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, nullptr, 0);
  }

  // GET /tilt : tilt settings for the remote page (public, read-only)
  static esp_err_t tilt_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    Settings s;
    {
      std::lock_guard<std::mutex> g(self->settings_mutex_);
      s = self->settings_;
    }
    char buf[96];
    snprintf(buf, sizeof(buf), "{\"dz\":%u,\"rg\":%u,\"ac\":%u,\"br\":%u}", s.tilt_dz, s.tilt_rg, s.accel, s.brake);
    return send_json_(req, buf);
  }

  // ---------- setup page ----------
  static esp_err_t config_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, self->config_html_, HTTPD_RESP_USE_STRLEN);
  }

  static esp_err_t settings_get_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    Settings s;
    {
      std::lock_guard<std::mutex> g(self->settings_mutex_);
      s = self->settings_;
    }
    std::string out;
    char buf[240];
    snprintf(buf, sizeof(buf),
             "{\"dz\":%u,\"rg\":%u,\"sm\":%u,\"st\":%u,\"ac\":%u,\"br\":%u,\"kk\":%u,"
             "\"hd\":%u,\"pins\":[%u,%u,%u,%u],",
             s.tilt_dz, s.tilt_rg, s.steer_mode, s.steer_thr, s.accel, s.brake, s.kick, s.hold, s.pins[0],
             s.pins[1], s.pins[2], s.pins[3]);
    out += buf;
    out += "\"allowed\":[";
    size_t n = 0;
    const uint8_t *list = allowed_pins_(n);
    for (size_t i = 0; i < n; i++) {
      if (i > 0)
        out += ',';
      out += std::to_string(list[i]);
    }
    out += "],\"fw\":\"";
#ifdef ESPHOME_VERSION
    out += ESPHOME_VERSION;
#endif
    out += "\",\"heap\":";
    out += std::to_string(static_cast<unsigned>(esp_get_free_heap_size()));
    out += "}";
    return send_json_(req, out);
  }

  // POST /api/settings  body: dz, rg, it, is, sm, st, p0..p3
  static esp_err_t settings_post_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    char body[320];
    if (!read_body_(req, body, sizeof(body)))
      return send_text_(req, "400 Bad Request", "{\"ok\":false,\"error\":\"Bad request.\"}");

    Settings ns;
    {
      std::lock_guard<std::mutex> g(self->settings_mutex_);
      ns = self->settings_;
    }
    int v;
    if (form_int_(body, "dz", &v)) ns.tilt_dz = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "rg", &v)) ns.tilt_rg = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "sm", &v)) ns.steer_mode = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "st", &v)) ns.steer_thr = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "ac", &v)) ns.accel = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "br", &v)) ns.brake = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "kk", &v)) ns.kick = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    if (form_int_(body, "hd", &v)) ns.hold = static_cast<uint8_t>(std::max(0, std::min(255, v)));
    const char *pin_keys[4] = {"p0", "p1", "p2", "p3"};
    for (int i = 0; i < 4; i++)
      if (form_int_(body, pin_keys[i], &v))
        ns.pins[i] = static_cast<uint8_t>(std::max(0, std::min(255, v)));

    if (!self->valid_(ns))
      return send_text_(req, "400 Bad Request",
                        "{\"ok\":false,\"error\":\"Invalid values: check the pins are allowed and different.\"}");

    bool pins_changed;
    {
      std::lock_guard<std::mutex> g(self->settings_mutex_);
      pins_changed = memcmp(ns.pins, self->settings_.pins, sizeof(ns.pins)) != 0;
      self->pending_ = ns;
    }
    self->pending_settings_.store(true);
    return send_json_(req, pins_changed ? "{\"ok\":true,\"reboot\":true}" : "{\"ok\":true,\"reboot\":false}");
  }

  // ---------- Wi-Fi ----------
  // GET /scan : start a scan; results are read from /networks a few seconds later
  static esp_err_t scan_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) == ESP_OK && mode == WIFI_MODE_AP)
      esp_wifi_set_mode(WIFI_MODE_APSTA);  // scanning needs the station side switched on
    wifi_scan_config_t cfg = {};
    cfg.show_hidden = false;
    cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    cfg.scan_time.active.min = 100;
    cfg.scan_time.active.max = 300;
#ifdef CONFIG_SOC_WIFI_SUPPORTED
    cfg.coex_background_scan = true;  // hop back to the current channel between channels
#endif
    esp_err_t err = esp_wifi_scan_start(&cfg, false);
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "Scan not started: %s", esp_err_to_name(err));
      return send_text_(req, "409 Conflict", "busy");
    }
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, nullptr, 0);
  }

  // GET /networks : [{"ssid":"..","rssi":-55,"lock":1}, ...]
  static esp_err_t networks_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    std::string out = "[";
    bool first = true;
    {
      wifi::ScanResultsLock lock(wifi::global_wifi_component);
      const auto &results = wifi::global_wifi_component->get_scan_result();
      for (const auto &scan : results) {
        bool with_auth = false;
        if (!wifi::should_show_scan_entry(results, scan, with_auth))
          continue;
        if (!first)
          out += ',';
        first = false;
        out += "{\"ssid\":\"";
        json_escape_(out, scan.get_ssid().c_str());
        out += "\",\"rssi\":";
        out += std::to_string(static_cast<int>(scan.get_rssi()));
        out += ",\"lock\":";
        out += with_auth ? "1" : "0";
        out += "}";
      }
    }
    out += "]";
    return send_json_(req, out);
  }

  // GET /status : {"connected":true,"ssid":"..","rssi":-55,"ip":"192.168.1.20","ap":false}
  static esp_err_t status_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    std::string out = "{";
    wifi_ap_record_t ap = {};
    bool connected = wifi::global_wifi_component->is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    out += connected ? "\"connected\":true" : "\"connected\":false";
    if (connected) {
      char ssid[33] = {0};
      memcpy(ssid, ap.ssid, 32);
      out += ",\"ssid\":\"";
      json_escape_(out, ssid);
      out += "\",\"rssi\":";
      out += std::to_string(static_cast<int>(ap.rssi));
      esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
      esp_netif_ip_info_t ip = {};
      if (netif != nullptr && esp_netif_get_ip_info(netif, &ip) == ESP_OK) {
        char buf[16];
        snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip.ip));
        out += ",\"ip\":\"";
        out += buf;
        out += "\"";
      }
    }
    out += wifi::global_wifi_component->is_ap_active() ? ",\"ap\":true}" : ",\"ap\":false}";
    return send_json_(req, out);
  }

  // POST /save  body: ssid=<urlencoded>&psk=<urlencoded>
  static esp_err_t save_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    char body[320];
    if (!read_body_(req, body, sizeof(body)))
      return send_text_(req, "400 Bad Request", "Bad request.");

    char raw[200];
    char ssid[33] = {0};
    char psk[65] = {0};
    if (httpd_query_key_value(body, "ssid", raw, sizeof(raw)) == ESP_OK)
      url_decode_(ssid, sizeof(ssid), raw);
    if (httpd_query_key_value(body, "psk", raw, sizeof(raw)) == ESP_OK)
      url_decode_(psk, sizeof(psk), raw);

    if (ssid[0] == '\0')
      return send_text_(req, "400 Bad Request", "Network name is required.");
    if (psk[0] != '\0' && strlen(psk) < 8)
      return send_text_(req, "400 Bad Request", "Password must be at least 8 characters.");

    memcpy(self->pending_ssid_, ssid, sizeof(ssid));
    memcpy(self->pending_psk_, psk, sizeof(psk));
    self->pending_wifi_.store(true);
    return httpd_resp_send(req, "Saved. The car is restarting.", HTTPD_RESP_USE_STRLEN);
  }

  // POST /forget : remove the stored network, go back to the SmartCar hotspot only
  static esp_err_t forget_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    self->pending_ssid_[0] = '\0';
    self->pending_psk_[0] = '\0';
    self->pending_wifi_.store(true);
    return httpd_resp_send(req, "Wi-Fi forgotten. The car restarts; the SmartCar hotspot appears after about 20 seconds.",
                           HTTPD_RESP_USE_STRLEN);
  }

  // ---------- firmware update ----------
  // POST /update  body: the raw firmware.ota.bin
  static esp_err_t update_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    size_t total = req->content_len;
    if (total < 4096)
      return send_text_(req, "400 Bad Request", "That does not look like a firmware file.");
    if (self->ota_active_.exchange(true))
      return send_text_(req, "409 Conflict", "An update is already running.");

    self->ramp_ = false;
    self->target_t_ = 0;
    self->target_s_ = 0;
    ESP_LOGI(TAG, "Firmware update started (%u bytes)", (unsigned) total);

    auto backend = ota::make_ota_backend();
    auto res = backend->begin(total);
    if (res != ota::OTA_RESPONSE_OK) {
      ESP_LOGE(TAG, "OTA begin failed: 0x%02x", (unsigned) res);
      self->ota_active_ = false;
      return send_text_(req, "500 Internal Server Error", "Could not start the update (image too large?).");
    }

    uint8_t buf[1024];
    size_t got = 0;
    int timeouts = 0;
    while (got < total) {
      size_t want = std::min(sizeof(buf), total - got);
      int r = httpd_req_recv(req, reinterpret_cast<char *>(buf), want);
      if (r == HTTPD_SOCK_ERR_TIMEOUT) {
        if (++timeouts > 10) {
          backend->abort();
          self->ota_active_ = false;
          return ESP_FAIL;
        }
        continue;
      }
      timeouts = 0;
      if (r <= 0) {
        backend->abort();
        self->ota_active_ = false;
        return ESP_FAIL;
      }
      res = backend->write(buf, static_cast<size_t>(r));
      if (res != ota::OTA_RESPONSE_OK) {
        ESP_LOGE(TAG, "OTA write failed: 0x%02x", (unsigned) res);
        backend->abort();
        self->ota_active_ = false;
        return send_text_(req, "500 Internal Server Error", "Writing to flash failed.");
      }
      got += static_cast<size_t>(r);
    }
    res = backend->end();
    if (res != ota::OTA_RESPONSE_OK) {
      ESP_LOGE(TAG, "OTA end failed: 0x%02x", (unsigned) res);
      self->ota_active_ = false;
      return send_text_(req, "500 Internal Server Error", "The file was rejected (wrong chip or damaged file?).");
    }
    ESP_LOGI(TAG, "Firmware update written, restarting");
    httpd_resp_send(req, "Update installed. The car is restarting.", HTTPD_RESP_USE_STRLEN);
    self->schedule_reboot_(1500);
    return ESP_OK;
  }

  // ---------- log & reboot ----------
  // GET /logs?from=<seq> : {"lines":["I[tag] text",...],"next":<seq>}
  static esp_err_t logs_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    uint32_t from = 0;
    char query[32];
    char val[16];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "from", val, sizeof(val)) == ESP_OK)
      from = static_cast<uint32_t>(strtoul(val, nullptr, 10));

    std::string out = "{\"lines\":[";
    uint32_t next;
    {
      std::lock_guard<std::mutex> g(self->log_mutex_);
      uint32_t seq = self->log_seq_;
      uint32_t oldest = seq > LOG_LINES ? seq - LOG_LINES : 0;
      if (from < oldest || from > seq)
        from = oldest;
      bool first = true;
      uint32_t i = from;
      for (; i < seq && out.size() < 6000; i++) {
        if (!first)
          out += ',';
        first = false;
        out += '"';
        json_escape_(out, self->log_[i % LOG_LINES].text);
        out += '"';
      }
      next = i;
    }
    out += "],\"next\":";
    out += std::to_string(next);
    out += "}";
    return send_json_(req, out);
  }

  static esp_err_t reboot_handler_(httpd_req_t *req) {
    auto *self = static_cast<RemoteHttps *>(req->user_ctx);
    if (!self->authorized_(req))
      return ESP_OK;
    self->schedule_reboot_(800);
    return httpd_resp_send(req, "Restarting.", HTTPD_RESP_USE_STRLEN);
  }

  // ---------- state ----------
  const char *html_{""};
  const char *config_html_{""};
  const char *cert_{""};
  const char *key_{""};
  std::string auth_header_;
  uint16_t port_{443};
  uint32_t failsafe_ms_{600};
  bool http_redirect_{true};

  Settings defaults_{SETTINGS_MAGIC, {4, 5, 6, 7}, 0, 25, 6, 25, 0, 0, 15, 3, 20, 35};
  Settings settings_{};
  Settings pending_{};
  std::mutex settings_mutex_;
  ESPPreferenceObject pref_;
  std::atomic<bool> pending_settings_{false};
  std::atomic<uint8_t> steer_mode_{0};
  std::atomic<uint8_t> steer_thr_{25};
  std::atomic<uint8_t> accel_{15};
  std::atomic<uint8_t> brake_{3};
  std::atomic<uint8_t> kick_{20};
  std::atomic<uint8_t> hold_{35};
  std::atomic<bool> ramp_{false};

  httpd_handle_t server_{nullptr};
  httpd_handle_t redirect_server_{nullptr};
  std::atomic<int> target_t_{0};
  std::atomic<int> target_s_{0};
  std::atomic<uint32_t> last_cmd_{0};
  float cur_t_{0};  // current drive level, -100..100 (main task only)
  int steer_dir_{0};
  uint32_t steer_started_{0};
  uint32_t last_update_{0};
  uint32_t duty_[4] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

  char pending_ssid_[33] = {0};
  char pending_psk_[65] = {0};
  std::atomic<bool> pending_wifi_{false};
  std::atomic<bool> reboot_pending_{false};
  std::atomic<uint32_t> reboot_at_{0};
  std::atomic<bool> ota_active_{false};

  std::mutex log_mutex_;
  LogEntry log_[LOG_LINES] = {};
  uint32_t log_seq_{0};
};

}  // namespace remote_https
}  // namespace esphome
