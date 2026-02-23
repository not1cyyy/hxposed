use crate::hypervisor::ops;
use crate::hypervisor::vmexit::vmcall_handler;
use crate::win::{ExAllocatePool2, KeQueryActiveProcessorCountEx, PoolFlags};
use alloc::boxed::Box;
use alloc::vec::Vec;
use hv::{GdtTss, InterruptDescriptorTable, SharedHostData};
use x86::segmentation::cs;

pub(crate) fn init_hypervisor() {
    log::info!("Allocating memory for the hypervisor...");

    let mem = unsafe {
        ExAllocatePool2(
            PoolFlags::NonPaged,
            hv::allocator::ALLOCATION_BYTES as _,
            0x2009,
        )
    };

    hv::allocator::init(mem as _);

    hv::platform_ops::init(Box::new(ops::WindowsOps));

    // Build one GdtTss per logical processor.
    // We call GdtTss::new_from_current() while pinned to each core so that each
    // entry captures the TSS descriptor live from that core's segment registers.
    // SharedHostData::gdts is indexed by the logical processor ID supplied to
    // VmxGuest/SvmGuest::initialize_host, so the Vec must be processor_count long.
    let processor_count = unsafe { KeQueryActiveProcessorCountEx(0xffff) } as usize;
    log::info!("Building host GDT/TSS for {} logical processor(s)...", processor_count);

    let mut gdts: Vec<GdtTss> = (0..processor_count)
        .map(|_| GdtTss::new_from_current())
        .collect();

    hv::platform_ops::get().run_on_all_processors(|index| {
        // Overwrite the pre-filled slot with a snapshot captured on this exact core.
        gdts[index as usize] = GdtTss::new_from_current();
        log::info!("Captured host GDT/TSS for processor {}", index);
    });

    // Build a single host IDT shared across all processors.
    // The IDT entries reference the host CS selector, which is uniform across
    // all cores. The interrupt handlers are located in hvcore and will panic on
    // any unexpected exception, keeping the host state deterministic.
    let host_cs = unsafe { cs() };
    log::info!("Building host IDT with CS selector {:?}...", host_cs);
    let host_idt = InterruptDescriptorTable::new(host_cs);

    log::info!("Host GDT/IDT isolation enabled.");

    let mut host_data = SharedHostData::default();
    host_data.vmcall_handler = Some(vmcall_handler);
    host_data.gdts = Some(gdts);
    host_data.idt = Some(host_idt);

    hv::virtualize_system(host_data);
}
