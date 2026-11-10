import base64
from pathlib import Path

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import logger, wifi
from esphome.components.esp32 import add_idf_sdkconfig_option
from esphome.const import CONF_ID, CONF_PORT

try:  # newer ESPHome excludes unused built-in IDF components by default
    from esphome.components.esp32 import include_builtin_idf_component
except ImportError:  # pragma: no cover
    include_builtin_idf_component = None

DEPENDENCIES = ["esp32", "wifi", "logger", "ota"]

remote_https_ns = cg.esphome_ns.namespace("remote_https")
RemoteHttps = remote_https_ns.class_("RemoteHttps", cg.Component)

CONF_DRIVE_FORWARD_PIN = "drive_forward_pin"
CONF_DRIVE_REVERSE_PIN = "drive_reverse_pin"
CONF_STEER_RIGHT_PIN = "steer_right_pin"
CONF_STEER_LEFT_PIN = "steer_left_pin"
CONF_STEER_PROPORTIONAL = "steer_proportional"
CONF_STEER_THRESHOLD = "steer_threshold"
CONF_TILT_DEADZONE = "tilt_deadzone"
CONF_TILT_RANGE = "tilt_range"
CONF_FAILSAFE_TIMEOUT = "failsafe_timeout"
CONF_ACCELERATION_TIME = "acceleration_time"
CONF_BRAKING_TIME = "braking_time"
CONF_STEER_KICK_TIME = "steer_kick_time"
CONF_STEER_HOLD_POWER = "steer_hold_power"
CONF_HTTP_REDIRECT = "http_redirect"
CONF_CONFIG_USERNAME = "config_username"
CONF_CONFIG_PASSWORD = "config_password"

PIN = cv.int_range(min=0, max=48)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(RemoteHttps),
        cv.Optional(CONF_PORT, default=443): cv.port,
        # Defaults only: the pins, steering and tilt values can be changed on the /config page.
        cv.Optional(CONF_DRIVE_FORWARD_PIN, default=4): PIN,
        cv.Optional(CONF_DRIVE_REVERSE_PIN, default=5): PIN,
        cv.Optional(CONF_STEER_RIGHT_PIN, default=6): PIN,
        cv.Optional(CONF_STEER_LEFT_PIN, default=7): PIN,
        cv.Optional(CONF_STEER_PROPORTIONAL, default=False): cv.boolean,
        cv.Optional(CONF_STEER_THRESHOLD, default="25%"): cv.percentage,
        cv.Optional(CONF_TILT_DEADZONE, default=6): cv.int_range(min=1, max=30),
        cv.Optional(CONF_TILT_RANGE, default=25): cv.int_range(min=5, max=80),
        cv.Optional(CONF_ACCELERATION_TIME, default="1.5s"): cv.All(
            cv.positive_time_period_milliseconds, cv.Range(min=cv.TimePeriod(milliseconds=200), max=cv.TimePeriod(milliseconds=5000))
        ),
        cv.Optional(CONF_BRAKING_TIME, default="0.3s"): cv.All(
            cv.positive_time_period_milliseconds, cv.Range(max=cv.TimePeriod(milliseconds=2000))
        ),
        cv.Optional(CONF_STEER_KICK_TIME, default="2s"): cv.All(
            cv.positive_time_period_milliseconds, cv.Range(min=cv.TimePeriod(milliseconds=200), max=cv.TimePeriod(milliseconds=5000))
        ),
        cv.Optional(CONF_STEER_HOLD_POWER, default="35%"): cv.All(cv.percentage, cv.Range(min=0.1, max=1.0)),
        cv.Optional(CONF_HTTP_REDIRECT, default=True): cv.boolean,
        cv.Optional(CONF_CONFIG_USERNAME, default="admin"): cv.string,
        cv.Optional(CONF_CONFIG_PASSWORD): cv.sensitive(cv.string),
        cv.Optional(CONF_FAILSAFE_TIMEOUT, default="600ms"): cv.positive_time_period_milliseconds,
    }
).extend(cv.COMPONENT_SCHEMA)


def _validate(config):
    pins = [
        config[CONF_DRIVE_FORWARD_PIN],
        config[CONF_DRIVE_REVERSE_PIN],
        config[CONF_STEER_RIGHT_PIN],
        config[CONF_STEER_LEFT_PIN],
    ]
    if len(set(pins)) != 4:
        raise cv.Invalid("The four motor pins must all be different")
    if config[CONF_TILT_RANGE] <= config[CONF_TILT_DEADZONE]:
        raise cv.Invalid("tilt_range must be larger than tilt_deadzone")
    return config


FINAL_VALIDATE_SCHEMA = None
CONFIG_SCHEMA = cv.All(CONFIG_SCHEMA, _validate)


async def to_code(config):
    here = Path(__file__).parent

    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    cg.add(var.set_html((here / "index.html").read_text(encoding="utf-8")))
    cg.add(var.set_config_html((here / "config.html").read_text(encoding="utf-8")))
    cg.add(var.set_cert((here / "cert.pem").read_text(encoding="utf-8")))
    cg.add(var.set_key((here / "key.pem").read_text(encoding="utf-8")))
    cg.add(var.set_port(config[CONF_PORT]))

    if CONF_CONFIG_PASSWORD in config:
        creds = f"{config[CONF_CONFIG_USERNAME]}:{config[CONF_CONFIG_PASSWORD]}"
        cg.add(var.set_config_auth("Basic " + base64.b64encode(creds.encode()).decode()))

    cg.add(
        var.set_default_pins(
            config[CONF_DRIVE_FORWARD_PIN],
            config[CONF_DRIVE_REVERSE_PIN],
            config[CONF_STEER_RIGHT_PIN],
            config[CONF_STEER_LEFT_PIN],
        )
    )
    cg.add(
        var.set_default_steer(
            config[CONF_STEER_PROPORTIONAL], round(config[CONF_STEER_THRESHOLD] * 100)
        )
    )
    cg.add(var.set_default_tilt(config[CONF_TILT_DEADZONE], config[CONF_TILT_RANGE]))
    cg.add(
        var.set_default_motion(
            round(config[CONF_ACCELERATION_TIME].total_milliseconds / 100),
            round(config[CONF_BRAKING_TIME].total_milliseconds / 100),
            round(config[CONF_STEER_KICK_TIME].total_milliseconds / 100),
            round(config[CONF_STEER_HOLD_POWER] * 100),
        )
    )
    cg.add(var.set_http_redirect(config[CONF_HTTP_REDIRECT]))
    cg.add(var.set_failsafe_ms(config[CONF_FAILSAFE_TIMEOUT].total_milliseconds))

    # Wi-Fi setup page reads scan results; debug page listens to the log
    wifi.request_wifi_scan_results()
    wifi.request_wifi_scan_results_lock()
    logger.request_log_listener()

    # TLS web server + LEDC PWM in ESP-IDF
    if include_builtin_idf_component is not None:
        for comp in (
            "esp_http_server",
            "esp-tls",
            "esp_https_server",
            "esp_driver_ledc",
            "esp_driver_gpio",
            "driver",
        ):
            include_builtin_idf_component(comp)
    add_idf_sdkconfig_option("CONFIG_ESP_HTTPS_SERVER_ENABLE", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_TLS_SERVER_AND_CLIENT", True)
