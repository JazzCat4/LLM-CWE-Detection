`include "1234_3.v"

// Testbench for 'test' module focusing on CWE-1191, CWE-1234, CWE-1262, CWE-1256, CWE-226
module tb_test;

    // DUT interface
    reg         clk;
    reg         rst;
    reg         write_en;
    reg         debug_mode;
    reg  [7:0]  data_in;
    wire [7:0]  protected_reg;

    // Instantiate DUT
    test dut (
        .clk(clk),
        .rst(rst),
        .write_en(write_en),
        .debug_mode(debug_mode),
        .data_in(data_in),
        .protected_reg(protected_reg)
    );

    // Clock generation
    initial clk = 0;
    always #5 clk = ~clk;

    // Simple task to step one clock
    task step;
    begin
        @(posedge clk);
        #1;
    end
    endtask

    initial begin
        // Initialize
        rst        = 1'b1;
        write_en   = 1'b0;
        debug_mode = 1'b0;
        data_in    = 8'h00;

        // Apply reset (CWE-226 guide: scrub on reset)
        step;
        rst = 1'b0;
        step;
        $display("After reset: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 1) Normal write path (baseline behavior)
        // Expect protected_reg to update when unlocked and write_en=1
        data_in  = 8'hAA;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("Normal write (unlocked): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 2) Lock the register using data_in==0xFF and write_en (CWE-1234/CWE-1262)
        data_in  = 8'hFF;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("After lock set: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 3) Attempt normal write while locked (should be blocked)
        data_in  = 8'h55;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("Normal write while locked (expected blocked): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 4) CWE-1191 / CWE-1234 / CWE-1262 / CWE-1256:
        // Debug mode overriding lock bit and allowing write to protected_reg
        debug_mode = 1'b1;
        data_in    = 8'h33;
        step;
        debug_mode = 1'b0;
        $display("Debug write while locked (lock bypass): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 5) CWE-1234: reset clears lock_bit, re-enabling normal writes
        rst = 1'b1;
        step;
        rst = 1'b0;
        step;
        $display("After reset (lock cleared): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 6) CWE-226: sensitive data not scrubbed on lock transition
        // Write a sensitive value, then lock; verify value persists
        data_in  = 8'hA5;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("Sensitive write before lock: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        data_in  = 8'hFF; // lock trigger
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("After lock (no scrub on transition): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 7) CWE-1191 / CWE-1256: show that any stimulus (no privilege gating)
        // can drive debug_mode and write_en to control protected_reg and lock_bit
        // Simulate "unprivileged" agent by just driving signals again
        debug_mode = 1'b1;
        data_in    = 8'h5A;
        step;
        debug_mode = 1'b0;
        $display("Unprivileged-like debug access: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        $display("Testbench completed.");
        $finish;
    end

endmodule
