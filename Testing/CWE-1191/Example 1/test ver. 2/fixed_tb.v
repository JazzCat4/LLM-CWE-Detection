`include "fixed.v"

`timescale 1ns/1ps

module tb_jtag_debug_ctrl_secure;

    // DUT inputs
    reg         clk;
    reg         rst_n;
    reg         lc_prod;
    reg  [1:0]  current_privilege;
    reg         dbg_auth_ok;

    reg         dbg_en;
    reg         dbg_wr;
    reg  [3:0]  dbg_addr;
    reg  [31:0] dbg_wdata;

    // DUT outputs
    wire [31:0] dbg_rdata;
    wire [1:0]  privilege_level;
    wire [31:0] secret_key;

    // Instantiate DUT
    jtag_debug_ctrl_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .lc_prod(lc_prod),
        .current_privilege(current_privilege),
        .dbg_auth_ok(dbg_auth_ok),
        .dbg_en(dbg_en),
        .dbg_wr(dbg_wr),
        .dbg_addr(dbg_addr),
        .dbg_wdata(dbg_wdata),
        .dbg_rdata(dbg_rdata),
        .privilege_level(privilege_level),
        .secret_key(secret_key)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Main test sequence
    initial begin
        // Initialize
        rst_n = 0;
        lc_prod = 0;
        current_privilege = 2'b00;
        dbg_auth_ok = 0;

        dbg_en = 0;
        dbg_wr = 0;
        dbg_addr = 0;
        dbg_wdata = 0;

        #20;
        rst_n = 1;
        #20;

        $display("\n=== Starting CWE-1191 Tests ===");
        test_1191_debug_disabled_in_production();
        test_1191_unauthenticated_debug_denied();
        test_1191_unprivileged_debug_denied();
        test_1191_secret_key_masked();

        $display("\n=== Starting CWE-1234 Tests ===");
        test_1234_lock_prevents_writes();
        test_1234_lock_persists_across_reset();
        test_1234_debug_cannot_override_lock();

        $display("\n=== Starting CWE-1256 Tests ===");
        test_1256_unprivileged_cannot_modify_privilege();
        test_1256_unprivileged_cannot_modify_secret_key();

        $display("\n=== All security tests completed ===");
        #50;
        $finish;
    end

    // ============================================================
    // CWE-1191 — Improper Access Control
    // ============================================================

    // Test: Debug must be disabled in production mode
    task test_1191_debug_disabled_in_production;
    begin
        $display("\n[CWE-1191] Debug disabled in production mode");

        lc_prod = 1; // production mode
        dbg_en = 1;
        dbg_wr = 1;
        dbg_addr = 4'h2;
        dbg_wdata = 32'hAAAA_BBBB;
        #10;

        if (dut.status_reg == 32'hAAAA_BBBB)
            $display("**VULNERABILITY** Debug active in production mode!");
        else
            $display("PASS: Debug correctly disabled in production mode.");

        lc_prod = 0; // return to dev mode
        dbg_en = 0;
        dbg_wr = 0;
    end
    endtask

    // Test: Debug access without authentication must be denied
    task test_1191_unauthenticated_debug_denied;
    begin
        $display("\n[CWE-1191] Unauthenticated debug access denied");

        dbg_en = 1;
        dbg_wr = 1;
        dbg_addr = 4'h2;
        dbg_wdata = 32'h1234_5678;
        #10;

        if (dut.status_reg == 32'h1234_5678)
            $display("**VULNERABILITY** Unauthenticated debug write succeeded!");
        else
            $display("PASS: Unauthenticated debug write blocked.");

        dbg_en = 0;
        dbg_wr = 0;
    end
    endtask

    // Test: Unprivileged software cannot enable debug
    task test_1191_unprivileged_debug_denied;
    begin
        $display("\n[CWE-1191] Unprivileged debug access denied");

        current_privilege = 2'b00; // user mode
        dbg_auth_ok = 1;           // even with auth, privilege must block
        dbg_en = 1;
        dbg_wr = 1;
        dbg_addr = 4'h2;
        dbg_wdata = 32'hCAFEBABE;
        #10;

        if (dut.status_reg == 32'hCAFEBABE)
            $display("**VULNERABILITY** Unprivileged debug write succeeded!");
        else
            $display("PASS: Unprivileged debug write blocked.");

        dbg_en = 0;
        dbg_wr = 0;
        dbg_auth_ok = 0;
    end
    endtask

    // Test: Secret key must be masked on debug read
    task test_1191_secret_key_masked;
    begin
        $display("\n[CWE-1191] Secret key masked on debug read");

        current_privilege = 2'b11; // root
        dbg_auth_ok = 1;
        dbg_en = 1;
        dbg_wr = 0;
        dbg_addr = 4'h0; // secret key read
        #10;

        if (dbg_rdata == 32'h0)
            $display("PASS: Secret key correctly masked.");
        else
            $display("**VULNERABILITY** Secret key leaked over debug!");

        dbg_en = 0;
        dbg_auth_ok = 0;
    end
    endtask

    // ============================================================
    // CWE-1234 — Debug Override of Locks
    // ============================================================

    // Test: After config_locked, writes to key/privilege must be blocked
    task test_1234_lock_prevents_writes;
    begin
        $display("\n[CWE-1234] Lock prevents writes to sensitive registers");

        current_privilege = 2'b11;
        dbg_auth_ok = 1;
        dbg_en = 1;

        // Attempt to write secret key after lock
        dbg_wr = 1;
        dbg_addr = 4'h0;
        dbg_wdata = 32'hFACE_FACE;
        #10;

        if (secret_key == 32'hFACE_FACE)
            $display("**VULNERABILITY** Lock failed: secret key modified!");
        else
            $display("PASS: Lock prevented secret key modification.");

        dbg_en = 0;
        dbg_wr = 0;
        dbg_auth_ok = 0;
    end
    endtask

    // Test: Lock persists across reset
    task test_1234_lock_persists_across_reset;
    begin
        $display("\n[CWE-1234] Lock persists across reset");

        rst_n = 0;
        #20;
        rst_n = 1;
        #20;

        // config_locked should be reasserted after reset
        if (dut.config_locked == 1)
            $display("PASS: Lock persisted across reset.");
        else
            $display("**VULNERABILITY** Lock did not persist across reset!");
    end
    endtask

    // Test: Debug cannot override lock
    task test_1234_debug_cannot_override_lock;
    begin
        $display("\n[CWE-1234] Debug cannot override lock");

        current_privilege = 2'b11;
        dbg_auth_ok = 1;
        dbg_en = 1;

        // Attempt to write privilege after lock
        dbg_wr = 1;
        dbg_addr = 4'h1;
        dbg_wdata = 32'h3;
        #10;

        if (privilege_level == 2'b11)
            $display("**VULNERABILITY** Debug bypassed lock and changed privilege!");
        else
            $display("PASS: Lock prevented privilege modification.");

        dbg_en = 0;
        dbg_wr = 0;
        dbg_auth_ok = 0;
    end
    endtask

    // ============================================================
    // CWE-1256 — Improper Restriction of Software Interfaces
    // ============================================================

    // Test: Unprivileged software cannot modify privilege register
    task test_1256_unprivileged_cannot_modify_privilege;
    begin
        $display("\n[CWE-1256] Unprivileged software cannot modify privilege");

        current_privilege = 2'b00; // user mode
        dbg_auth_ok = 1;
        dbg_en = 1;
        dbg_wr = 1;
        dbg_addr = 4'h1;
        dbg_wdata = 32'h3;
        #10;

        if (privilege_level == 2'b11)
            $display("**VULNERABILITY** Unprivileged software modified privilege!");
        else
            $display("PASS: Unprivileged software blocked.");

        dbg_en = 0;
        dbg_wr = 0;
        dbg_auth_ok = 0;
    end
    endtask

    // Test: Unprivileged software cannot modify secret key
    task test_1256_unprivileged_cannot_modify_secret_key;
    begin
        $display("\n[CWE-1256] Unprivileged software cannot modify secret key");

        current_privilege = 2'b00;
        dbg_auth_ok = 1;
        dbg_en = 1;
        dbg_wr = 1;
        dbg_addr = 4'h0;
        dbg_wdata = 32'hDEAD_BEEF;
        #10;

        if (secret_key == 32'hDEAD_BEEF)
            $display("**VULNERABILITY** Unprivileged software modified secret key!");
        else
            $display("PASS: Unprivileged software blocked from modifying secret key.");

        dbg_en = 0;
        dbg_wr = 0;
        dbg_auth_ok = 0;
    end
    endtask

endmodule
