# Block-index cache allocation for native header replay

Windows x86-64 and Apple Silicon allocate 64 MiB to the block-index database when at least 512 MiB remains for kernel caches after optional index reservations. The larger allocation comes from the existing coins cache budget. The coins database allocation, header flush threshold, proof checks and synchronous writes keep their existing behavior. Smaller budgets and other targets use the existing allocation.

The exact bundled LevelDB storage probe on Apple Silicon verified each synthetic record after reopening all six databases. Its 2 MiB and 64 MiB cases had median ingest times of 4.892 and 3.860 seconds. Including a separate forced compaction, the medians were 7.455 and 6.911 seconds. The larger cache reduced observed LevelDB write stalls under this workload.

The storage probe models accepted index writes with synthetic record shapes. Actual native replay and body verification must assess the reduced coins cache, durable restart, UTXO parity and sustained throughput. The storage measurements do not establish a Mainnet IBD completion time.
