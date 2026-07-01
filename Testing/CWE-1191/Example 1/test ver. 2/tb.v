`include "Example1.v"
`timescale 1ns/1ps

module tb_jtag_debug_ctrl;

    // DUT inputs
    reg         clk;
    reg         rst_n;
    reg         dbg_en;
    reg         dbg_wr;
    reg  [3:0]  dbg_addr;
    reg  [31:0] dbg_wdata;

    // DUT outputs
    wire [31:0] dbg_rdata;
    wire [1:0]  privilege_level;
    wire [31:0] secret_key;

    // Hypothetical lock bit (not in DUT, used to model CWE-1234)
    reg         lock_bit;

    // Instantiate DUT
    Ex1 dut (
        .clk             (clk),
        .rst_n           (rst_n),
        .dbg_en          (dbg_en),
        .dbg_wr          (dbg_wr),
        .dbg_addr        (dbg_addr),
        .dbg_wdata       (dbg_wdata),
        .dbg_rdata       (dbg_rdata),
        .privilege_level (privilege_level),
        .secret_key      (secret_key)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Reset and main test sequence
    initial begin
        // Initialize
        rst_n      = 0;
        dbg_en     = 0;
        dbg_wr     = 0;
        dbg_addr   = 4'h0;
        dbg_wdata  = 32'h0;
        lock_bit   = 0;

        // Apply reset
        #20;
        rst_n = 1;
        #20;

        $display("=== Starting CWE-1191 tests ===");
        test_1191_unauthorized_debug_write_key();
        test_1191_unauthorized_read_key();
        test_1191_unprivileged_enable_debug();

        $display("=== Starting CWE-1234 tests ===");
        test_1234_lock_override_privilege();
        test_1234_lock_persistence_reset();

        $display("=== Starting CWE-1256 tests ===");
        test_1256_software_cannot_modify_privilege();
        test_1256_software_cannot_modify_secret_key();

        $display("=== Security testbench completed ===");
        #50;
        $finish;
    end

    // -------------------------------
    // CWE-1191: Improper access control
    // -------------------------------

    // Test: Attempt to write secret key via debug without any authentication
    task test_1191_unauthorized_debug_write_key;
    begin
        $display("\n[CWE-1191] Test: Unauthorized debug write to secret key");

        // Attempt write
        dbg_en   = 1;
        dbg_wr   = 1;
        dbg_addr = 4'h0;              // secret_key_reg
        dbg_wdata = 32'hBAD0_BAD0;
        #10;

        // Check if write succeeded (vulnerability)
        if (secret_key == 32'hBAD0_BAD0) begin
            $display("**VULNERABILITY** CWE-1191: Unauthorized debug write to secret_key succeeded.");
        end else begin
            $display("PASS: Unauthorized debug write to secret_key was blocked.");
        end

        // Cleanup
        dbg_en   = 0;
        dbg_wr   = 0;
        #10;
    end
    endtask

    // Test: Attempt to read secret key via debug without any authentication
    task test_1191_unauthorized_read_key;
    begin
        $display("\n[CWE-1191] Test: Unauthorized debug read of secret key");

        // Ensure secret_key has some non-trivial value (from reset or previous write)
        $display("Current secret_key = 0x%08h", secret_key);

        // Attempt read
        dbg_en   = 1;
        dbg_wr   = 0;
        dbg_addr = 4'h0;              // secret_key_reg
        #10;

        // Check if dbg_rdata exposes secret_key (vulnerability)
        if (dbg_rdata == secret_key) begin
            $display("**VULNERABILITY** CWE-1191: Secret key leaked over debug interface.");
        end else begin
            $display("PASS: Secret key not exposed over debug interface.");
        end

        // Cleanup
        dbg_en   = 0;
        #10;
    end
    endtask

    // Test: Simulate unprivileged context enabling debug
    task test_1191_unprivileged_enable_debug;
    begin
        $display("\n[CWE-1191] Test: Unprivileged enable of debug interface");

        // Assume privilege_level == 0 is unprivileged (after reset)
        $display("Initial privilege_level = %0d", privilege_level);

        // Unprivileged software attempts to enable debug
        dbg_en = 1;
        #10;

        // In a secure design, there should be an internal gate; here we only observe behavior
        // Try to write privilege via debug to see if debug is effectively active
        dbg_wr   = 1;
        dbg_addr = 4'h1;              // privilege_reg
        dbg_wdata = 32'h3;            // attempt root
        #10;

        if (privilege_level == 2'b11) begin
            $display("**VULNERABILITY** CWE-1191: Unprivileged context enabled debug and escalated privilege.");
        end else begin
            $display("PASS: Unprivileged context could not use debug to change privilege.");
        end

        dbg_en = 0;
        dbg_wr = 0;
        #10;
    end
    endtask

    // -------------------------------
    // CWE-1234: Debug overrides locks
    // -------------------------------

    // Test: Hypothetical lock bit set, debug still overrides privilege
    task test_1234_lock_override_privilege;
    begin
        $display("\n[CWE-1234] Test: Debug override of hypothetical lock bit on privilege_reg");

        // Simulate lock bit set (system thinks privilege_reg is locked)
        lock_bit = 1;
        $display("Lock bit set to 1 (hypothetical).");

        // Attempt to change privilege via debug
        dbg_en   = 1;
        dbg_wr   = 1;
        dbg_addr = 4'h1;              // privilege_reg
        dbg_wdata = 32'h3;            // attempt root
        #10;

        if (lock_bit == 1 && privilege_level == 2'b11) begin
            $display("**VULNERABILITY** CWE-1234: Debug interface bypassed lock bit and modified privilege_level.");
        end else begin
            $display("PASS: Lock bit prevented debug modification of privilege_level (hypothetical).");
        end

        dbg_en   = 0;
        dbg_wr   = 0;
        lock_bit = 0;
        #10;
    end
    endtask

    // Test: Lock persistence across reset while debug active
    task test_1234_lock_persistence_reset;
    begin
        $display("\n[CWE-1234] Test: Lock persistence across reset with debug activity");

        // Set hypothetical lock bit
        lock_bit = 1;

        // Apply reset while debug is asserted
        dbg_en = 1;
        rst_n  = 0;
        #20;
        rst_n  = 1;
        #20;

        // After reset, privilege_level should be user (00), but lock_bit conceptually should still protect
        $display("After reset: privilege_level = %0d, lock_bit = %0d", privilege_level, lock_bit);

        // Attempt debug write again
        dbg_wr   = 1;
        dbg_addr = 4'h1;
        dbg_wdata = 32'h3;
        #10;

        if (lock_bit == 1 && privilege_level == 2'b11) begin
            $display("**VULNERABILITY** CWE-1234: Debug + reset allowed privilege change despite lock bit.");
        end else begin
            $display("PASS: Lock bit conceptually persisted across reset and blocked debug writes.");
        end

        dbg_en   = 0;
        dbg_wr   = 0;
        lock_bit = 0;
        #10;
    end
    endtask

    // -------------------------------
    // CWE-1256: Improper restriction of software interfaces
    // -------------------------------

    // Test: Software-accessible debug interface modifies privilege_level (hardware-only feature)
    task test_1256_software_cannot_modify_privilege;
    begin
        $display("\n[CWE-1256] Test: Software-accessible debug interface modifying privilege_level");

        // Assume software (unprivileged) can drive dbg_* signals
        privilege_reg_info();

        // Attempt to change privilege via debug
        dbg_en   = 1;
        dbg_wr   = 1;
        dbg_addr = 4'h1;
        dbg_wdata = 32'h3;
        #10;

        if (privilege_level == 2'b11) begin
            $display("**VULNERABILITY** CWE-1256: Software-accessible debug interface changed privilege_level (hardware-only control).");
        end else begin
            $display("PASS: Software-accessible debug interface could not change privilege_level.");
        end

        dbg_en   = 0;
        dbg_wr   = 0;
        #10;
    end
    endtask

    // Test: Software-accessible debug interface modifies secret_key (hardware-only feature)
    task test_1256_software_cannot_modify_secret_key;
    begin
        $display("\n[CWE-1256] Test: Software-accessible debug interface modifying secret_key");

        $display("Initial secret_key = 0x%08h", secret_key);

        // Attempt to change secret_key via debug
        dbg_en   = 1;
        dbg_wr   = 1;
        dbg_addr = 4'h0;
        dbg_wdata = 32'hFACE_FACE;
        #10;

        if (secret_key == 32'hFACE_FACE) begin
            $display("**VULNERABILITY** CWE-1256: Software-accessible debug interface modified secret_key (hardware-only control).");
        end else begin
            $display("PASS: Software-accessible debug interface could not modify secret_key.");
        end

        dbg_en   = 0;
        dbg_wr   = 0;
        #10;
    end
    endtask

    // Helper: print privilege info
    task privilege_reg_info;
    begin
        $display("Current privilege_level = %0d", privilege_level);
    end
    endtask

endmodule
