# Bug Report Data — ELAN Touchpad Dead on Lenovo Legion 5 15ACH6H

## Summary

ELAN06FA touchpad initializes and reports capabilities via I2C HID but
generates zero touch/click events. Root cause: ACPI DSDT specifies I2C
bus speed of 400kHz but i2c_designware driver overrides to 100kHz due to
a known firmware bug. The ELAN06FA touchpad cannot transfer data reliably
at 100kHz.

Reproduced on two different Linux distributions, same hardware.

---

## Hardware

| Field | Value |
|---|---|
| Manufacturer | LENOVO |
| Model | Legion 5 15ACH6H |
| Product ID | 82JU |
| CPU | AMD Ryzen 7 5800H (Cezanne) |
| Touchpad | ELAN06FA:00, Vendor 04F3, Product 31DD |
| I2C Controller | AMDI0010:01 (Synopsys DesignWare) |
| ACPI Path | \_SB_.I2CB |

---

## Reproduction

**Distro 1:** Debian 13.4 (Trixie), kernel 6.12.73+deb13-amd64
**Distro 2:** RHEL 10.1, kernel 6.12.0-124.56.1.el10_1.x86_64

Steps:
1. Boot either distro on Lenovo Legion 5 15ACH6H (82JU)
2. Touch or click the touchpad
3. Run `sudo evtest /dev/input/event7` and touch pad — no events appear

---

## Kernel Log Evidence

```
[    0.311276] i2c_designware AMDI0010:01: [Firmware Bug]: DSDT uses known not-working I2C bus speed 400000, forcing it to 100000
[    1.150076] input: ELAN06FA:00 04F3:31DD Mouse as /devices/platform/AMDI0010:01/i2c-0/...
[    1.150187] input: ELAN06FA:00 04F3:31DD Touchpad as /devices/platform/AMDI0010:01/i2c-0/...
[    1.264818] input: ELAN06FA:00 04F3:31DD Mouse as /devices/platform/AMDI0010:01/i2c-0/...
[    1.264898] input: ELAN06FA:00 04F3:31DD Touchpad as /devices/platform/AMDI0010:01/i2c-0/...
```

Device initializes and reports capabilities (ACPI-cached) but I2C
data transfer fails at 100kHz — no touch events generated.

---

## evtest — Capabilities Present, Zero Events on Touch

```
Input device ID: bus 0x18 vendor 0x4f3 product 0x31dd version 0x100
Input device name: "ELAN06FA:00 04F3:31DD Touchpad"
Supported events:
  Event type 1 (EV_KEY): BTN_LEFT, BTN_TOUCH, BTN_TOOL_FINGER ...
  Event type 3 (EV_ABS):
    ABS_X: Min 0, Max 3217, Resolution 32
    ABS_Y: (present)
```

No events appear on touch. Physical click (BTN_LEFT) also silent.

---

## X11 Log — Device Removed Immediately After Recognition

```
[11.400] event7 - ELAN06FA:00 04F3:31DD Touchpad: device is a touchpad
[11.401] event7 - ELAN06FA:00 04F3:31DD Touchpad: device removed
[11.460] libinput: ELAN06FA:00 04F3:31DD Touchpad: Step value 0 was provided
```

hid-generic → hid-multitouch rebind causes device removal.
On rebind, libinput receives Step value 0 — likely I2C failure
during capability re-read at 100kHz.

---

## Diagnosis

The i2c_designware driver overrides DSDT 400kHz to 100kHz (known workaround
for this controller variant). The ELAN06FA requires 400kHz for reliable
I2C HID data transfer. At 100kHz:
- Device initializes (ACPI-cached capabilities visible)
- Actual touch data transfers fail silently
- No input events generated

---

## Potential Fix Approaches

1. **Kernel quirk** — device-specific quirk in i2c_designware or
   i2c_hid_acpi to use 400kHz for AMDI0010:01 + ELAN06FA:00

2. **Kernel parameter to test** — `i2c_designware.timings=0,400000`

3. **SSDT override** — custom ACPI table to correct I2C speed for \_SB_.I2CB

---

## Where to Report

- **kernel.org Bugzilla:** Drivers > I2C/SMBus
  Title: "i2c_designware: ELAN06FA touchpad dead at 100kHz on Lenovo Legion 5 15ACH6H (AMDI0010:01)"

- **Red Hat Bugzilla:** RHEL 10, component "kernel"

- **Debian BTS:** `reportbug linux` — Debian 13.4, kernel 6.12.73

---

## Search Before Filing

Search: `i2c_designware AMDI0010 ELAN06FA 400000`
Also check: Arch Linux / Gentoo bug trackers, lkml.org archives,
Lenovo Linux community forums — may already be reported.
