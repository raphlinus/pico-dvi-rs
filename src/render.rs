mod palette;
mod queue;

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, Ordering};

use rp_pico::{
    hal::{sio::SioFifo, Sio},
    pac,
};

use crate::{
    dvi::{tmds::TmdsPair, VERTICAL_REPEAT},
    scanlist::{Scanlist, ScanlistBuilder},
};

use self::{palette::BW_PALETTE, queue::Queue};

pub const N_LINE_BUFS: usize = 4;

pub struct ScanRender {
    scanlist: Scanlist,
    stripe_remaining: u32,
    scan_ptr: *const u32,
    scan_next: *const u32,
    assigned: [bool; N_LINE_BUFS],
    fifo: SioFifo,
}

/// Size of a line buffer in u32 units.
const LINE_BUF_SIZE: usize = 256;

static mut LINE_BUFS: [LineBuf; N_LINE_BUFS] = [LineBuf::zero(); N_LINE_BUFS];
const ATOMIC_FALSE: AtomicBool = AtomicBool::new(false);
static PENDING: [AtomicBool; N_LINE_BUFS] = [ATOMIC_FALSE; N_LINE_BUFS];

/// The maximum number of lines that can be scheduled on core1.
const MAX_CORE1_PENDING: usize = 1;
const LINE_QUEUE_SIZE: usize = MAX_CORE1_PENDING * 2;
pub static CORE1_QUEUE: Queue<LINE_QUEUE_SIZE> = Queue::new();

#[derive(Clone, Copy)]
pub struct LineBuf {
    buf: [u32; LINE_BUF_SIZE],
}

impl LineBuf {
    const fn zero() -> Self {
        let buf = [0; LINE_BUF_SIZE];
        LineBuf { buf }
    }
}

core::arch::global_asm! {
    include_str!("render.asm"),
    options(raw)
}

extern "C" {
    fn tmds_scan(
        scan_list: *const u32,
        input: *const u32,
        output: *mut TmdsPair,
        stride: u32,
    ) -> *const u32;

    /// Delay approx 3x the argument clock cycles.
    fn microdelay(delay: u32);
}

fn rgb(r: u8, g: u8, b: u8) -> [TmdsPair; 3] {
    [
        TmdsPair::encode_balanced_approx(b),
        TmdsPair::encode_balanced_approx(g),
        TmdsPair::encode_balanced_approx(r),
    ]
}

impl ScanRender {
    pub fn new() -> Self {
        let mut sb = ScanlistBuilder::new(640, 480 / VERTICAL_REPEAT as u32);
        sb.begin_stripe(320 / VERTICAL_REPEAT as u32);
        sb.solid(92, rgb(0xc0, 0xc0, 0xc0));
        sb.solid(90, rgb(0xc0, 0xc0, 0));
        sb.solid(92, rgb(0, 0xc0, 0xc0));
        sb.solid(92, rgb(0, 0xc0, 0x0));
        sb.solid(92, rgb(0xc0, 0, 0xc0));
        sb.solid(90, rgb(0xc0, 0, 0));
        sb.solid(92, rgb(0, 0, 0xc0));
        sb.end_stripe();
        sb.begin_stripe(40 / VERTICAL_REPEAT as u32);
        sb.solid(92, rgb(0, 0, 0xc0));
        sb.solid(90, rgb(0x13, 0x13, 0x13));
        sb.solid(92, rgb(0xc0, 0, 0xc0));
        sb.solid(92, rgb(0x13, 0x13, 0x13));
        sb.solid(92, rgb(0, 0xc0, 0xc0));
        sb.solid(90, rgb(0x13, 0x13, 0x13));
        sb.solid(92, rgb(0xc0, 0xc0, 0xc0));
        sb.end_stripe();
        sb.begin_stripe(60 / VERTICAL_REPEAT as u32);
        sb.solid(114, rgb(0, 0x21, 0x4c));
        sb.solid(114, rgb(0xff, 0xff, 0xff));
        sb.solid(114, rgb(0x32, 0, 0x6a));
        sb.solid(116, rgb(0x13, 0x13, 0x13));
        sb.solid(30, rgb(0x09, 0x09, 0x09));
        sb.solid(30, rgb(0x13, 0x13, 0x13));
        sb.solid(30, rgb(0x1d, 0x1d, 0x1d));
        sb.solid(92, rgb(0x13, 0x13, 0x13));
        sb.end_stripe();
        sb.begin_stripe(60 / VERTICAL_REPEAT as u32);
        sb.pal_1bpp(96, &BW_PALETTE);
        sb.solid(544, rgb(0x13, 0x13, 0x13));
        sb.end_stripe();
        let scanlist = sb.build();
        let stripe_remaining = 0;
        let scan_ptr = core::ptr::null();
        let scan_next = core::ptr::null();
        // Safety: it makes sense for two cores to both have access to the
        // fifo, as it's designed for that purpose. A better PAC API might
        // allow us to express this safely.
        let pac = unsafe { pac::Peripherals::steal() };
        let sio = Sio::new(pac.SIO);
        let fifo = sio.fifo;
        ScanRender {
            scanlist,
            stripe_remaining,
            scan_ptr,
            scan_next,
            assigned: [false; N_LINE_BUFS],
            fifo,
        }
    }

    #[link_section = ".data"]
    #[inline(never)]
    pub fn render_scanline(&mut self, tmds_buf: &mut [TmdsPair], y: u32, available: bool) {
        unsafe {
            if y == 0 {
                self.scan_next = self.scanlist.get().as_ptr();
            }
            if self.stripe_remaining == 0 {
                self.stripe_remaining = self.scan_next.read();
                self.scan_ptr = self.scan_next.add(1);
                // TODO: set desperate scan_next
            }
            if available {
                let line_ix = y as usize % N_LINE_BUFS;
                let line_buf_ptr = LINE_BUFS[line_ix].buf.as_ptr();
                self.scan_next =
                    tmds_scan(self.scan_ptr, line_buf_ptr, tmds_buf.as_mut_ptr(), 1280);
            }
            self.stripe_remaining -= 1;
        }
    }

    #[link_section = ".data"]
    pub fn is_line_available(&self, y: u32) -> bool {
        let line_ix = y as usize % N_LINE_BUFS;
        self.assigned[line_ix] && !PENDING[line_ix].load(Ordering::Relaxed)
    }

    #[link_section = ".data"]
    pub fn schedule_line_render(&mut self, y: u32) {
        let line_ix = y as usize % N_LINE_BUFS;
        if PENDING[line_ix].load(Ordering::Relaxed) {
            self.assigned[line_ix] = false;
            return;
        }
        if CORE1_QUEUE.len() < MAX_CORE1_PENDING {
            // schedule on core1
            PENDING[line_ix].store(true, Ordering::Relaxed);
            CORE1_QUEUE.push_unchecked(line_ix as u32);
            self.assigned[line_ix] = true;
        } else {
            // try to schedule on core0
            if self.fifo.is_write_ready() {
                PENDING[line_ix].store(true, Ordering::Relaxed);
                // Writes to channels are generally considered to be release,
                // but the implementation in rp2040-hal lacks such a fence, so
                // we include it explicitly.
                compiler_fence(Ordering::Release);
                self.fifo.write(line_ix as u32);
                self.assigned[line_ix] = true;
            } else {
                self.assigned[line_ix] = false;
            }
        }
    }
}

/// Entry point for rendering a line.
///
/// This can be called by either core.
#[link_section = ".data"]
pub unsafe fn render_line(line_ix: u32, core: u32) {
    let line_buf = &mut LINE_BUFS[line_ix as usize];
    render_line_inner(line_buf);
    line_buf.buf[1] = core;
    PENDING[line_ix as usize].store(false, Ordering::Release);
}

static COUNT: AtomicU32 = AtomicU32::new(0);

#[link_section = ".data"]
fn render_line_inner(line_buf: &mut LineBuf) {
    let x = COUNT.load(Ordering::Relaxed);
    COUNT.store(x + 1, Ordering::Relaxed);
    line_buf.buf[0] = 0x55555555;
    line_buf.buf[1] = 0xaaaaaaaa;
    line_buf.buf[2] = x;
    unsafe {
        microdelay(1 + x / 100);
    }
}
