#![no_std]
#![no_main]

use core::arch::global_asm;

use defmt_rtt as _;
use panic_probe as _; // TODO: remove if you need 5kb of space, since panicking + formatting machinery is huge

use cortex_m::delay::Delay;
use defmt::{dbg, info};
use embedded_hal::digital::v2::OutputPin;
use rp_pico::{
    hal::{dma::DMAExt, gpio::PinState, pwm, sio::Sio, watchdog::Watchdog, Clock},
    pac
};

rp_pico::hal::bsp_pins!(
    Gpio13 { name: led },
    Gpio16 { name: clock_pos },
    Gpio17 { name: clock_neg },
    Gpio18 { name: red_pos },
    Gpio19 { name: red_neg },
    Gpio20 { name: green_pos },
    Gpio21 { name: green_neg },
    Gpio22 { name: blue_pos },
    Gpio23 { name: blue_neg },
);

use crate::{
    clock::init_clocks,
    dvi::serializer::{DviClockPins, DviDataPins, DviSerializer},
};

mod clock;
mod dvi;
mod framebuffer;
mod link;

global_asm! {
    "
    .section .text
    .align 4
    data_cpy_table:
     .word _scratch_x_source
     .word _scratch_x_start
     .word _scratch_x_end
     .word _scratch_y_source
     .word _scratch_y_start
     .word _scratch_y_end
     .word 0
    .global __pre_init
    .type __pre_init,%function
    .thumb_func
    __pre_init:
     push {{r4, lr}}
     ldr r4, =data_cpy_table

    1:
     ldmia r4!, {{r1-r3}}
     cmp r1, #0
     beq 2f
     bl data_cpy
     b 1b
    2:
     pop {{r4, pc}}
     data_cpy_loop:
     ldm r1!, {{r0}}
     stm r2!, {{r0}}
     data_cpy:
     cmp r2, r3
     blo data_cpy_loop
     bx lr
    "
}

// Separate macro annotated function to make rust-analyzer fixes apply better
#[rp_pico::entry]
fn macro_entry() -> ! {
    entry();
}

fn entry() -> ! {
    info!("Program start");

    let mut peripherals = pac::Peripherals::take().unwrap();
    let core_peripherals = pac::CorePeripherals::take().unwrap();

    sysinfo(&peripherals.SYSINFO);

    let mut watchdog = Watchdog::new(peripherals.WATCHDOG);
    let single_cycle_io = Sio::new(peripherals.SIO);

    // External high-speed crystal on the pico board is 12Mhz
    let clocks = init_clocks(
        peripherals.XOSC,
        peripherals.ROSC,
        peripherals.CLOCKS,
        peripherals.PLL_SYS,
        peripherals.PLL_USB,
        &mut peripherals.RESETS,
        &mut watchdog,
    );

    let pins = Pins::new(
        peripherals.IO_BANK0,
        peripherals.PADS_BANK0,
        single_cycle_io.gpio_bank0,
        &mut peripherals.RESETS,
    );

    let mut led_pin = pins.led.into_push_pull_output_in_state(PinState::Low);

    let mut delay = Delay::new(
        core_peripherals.SYST,
        dbg!(clocks.system_clock.freq().to_Hz()),
    );

    let pwm_slices = pwm::Slices::new(peripherals.PWM, &mut peripherals.RESETS);
    let dma = peripherals.DMA.split(&mut peripherals.RESETS);

    let dvi = DviSerializer::new(
        peripherals.PIO0,
        &mut peripherals.RESETS,
        DviDataPins {
            red_pos: pins.red_pos,
            red_neg: pins.red_neg,
            green_pos: pins.green_pos,
            green_neg: pins.green_neg,
            blue_pos: pins.blue_pos,
            blue_neg: pins.blue_neg,
        },
        DviClockPins {
            clock_pos: pins.clock_pos,
            clock_neg: pins.clock_neg,
            pwm_slice: pwm_slices.pwm0,
        },
    );

    // dvi.enable();

    rom();
    ram();
    ram_x();
    ram_y();

    unsafe { dbg!(&framebuffer::FRAMEBUFFER_16BPP as *const _) };
    unsafe { dbg!(&framebuffer::FRAMEBUFFER_8BPP as *const _) };

    loop {
        info!("high");
        led_pin.set_high().unwrap();
        delay.delay_ms(500);
        info!("low");
        led_pin.set_low().unwrap();
        delay.delay_ms(500);
    }
}

fn sysinfo(sysinfo: &pac::SYSINFO) {
    let is_fpga = sysinfo.platform.read().fpga().bit();
    let is_asic = sysinfo.platform.read().asic().bit();
    let git_hash = sysinfo.gitref_rp2040.read().bits();
    let manufacturer = sysinfo.chip_id.read().manufacturer().bits();
    let part = sysinfo.chip_id.read().part().bits();
    let revision = sysinfo.chip_id.read().revision().bits();

    info!(
        "SYSINFO
platform:
    FPGA: {=bool}
    ASIC: {=bool}
gitref_rp2040: {=u32:x}
chip_id:
    manufacturer: {=u16:X}
    part:         {=u16}
    revision:     {=u8}",
        is_fpga, is_asic, git_hash, manufacturer, part, revision
    );
}

// Functions and statics are placed in rom by default
fn rom() {
    dbg!(rom as fn() as *const ());
}

// This function will be placed in ram
#[link_section = link!(ram, ram)]
fn ram() {
    dbg!(ram as fn() as *const ());
}

// This function will be placed in ram
#[link_section = link!(scratch x, ram_x)]
fn ram_x() {
    dbg!(ram_x as fn() as *const ());
}

// This function will be placed in ram
#[link_section = link!(scratch y, ram_y)]
fn ram_y() {
    dbg!(ram_y as fn() as *const ());
}
