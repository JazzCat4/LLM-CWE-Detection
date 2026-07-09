`timescale 1ns/1ps
`include "fixed.v"
module test_secure_tb;

    reg         clk;
    reg         rst;
    reg         glitch_detect;
    reg  [7:0]  data_in;
    reg  [7:0]  mask_in;
    wire [7:0]  data_out;

    // Instantiate DUT
    test_secure dut (
        .clk(clk),
        .rst(rst),
        .glitch_detect(glitch_detect),
        .data_in(data_in),
        .mask_in(mask_in),
        .data_out(data_out)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Run one secure round
    task run_round(input [7:0] din, input [7:0] min);
        integer i;
        begin
            data_in  = din;
            mask_in  = min;
            glitch_detect = 0;

            for (i = 0; i < 9; i = i + 1)
                @(posedge clk);
        end
    endtask

    // Toggle monitor (side-channel proxy)
    reg [7:0] last_data_out;
    integer toggle_count;

    task measure_toggles(input [7:0] din, input [7:0] min, output integer toggles);
        integer i;
        begin
            toggles = 0;
            last_data_out = data_out;
            data_in = din;
            mask_in = min;

            for (i = 0; i < 9; i = i + 1) begin
                @(posedge clk);
                if (data_out !== last_data_out) begin
                    toggles = toggles + 1;
                    last_data_out = data_out;
                end
            end
        end
    endtask

    // Glitch injection
    task inject_glitch;
        begin
            glitch_detect = 1;
            @(posedge clk);
            glitch_detect = 0;
        end
    endtask

    // CWE-226: scrubbing test
    task check_scrub;
        begin
            run_round(8'hFF, 8'h3C);
            $display("[CWE-226] After first round, data_out = 0x%0h", data_out);

            run_round(8'h00, 8'h3C);
            $display("[CWE-226] After second round, data_out = 0x%0h", data_out);

            if (data_out == 8'h00)
                $display("[CWE-226] PASS: scrubbing between rounds.");
            else
                $display("[CWE-226] FAIL: scrubbing missing.");
        end
    endtask

    // CWE-1300: constant-time structural check
    task check_side_channel;
        integer t1, t2;
        begin
            measure_toggles(8'h00, 8'hA5, t1);
            measure_toggles(8'hFF, 8'hA5, t2);

            $display("[CWE-1300] Toggles for 0x00 = %0d", t1);
            $display("[CWE-1300] Toggles for 0xFF = %0d", t2);

            if (t1 == t2)
                $display("[CWE-1300] PASS: structural constant-time behavior.");
            else
                $display("[CWE-1300] WARN: toggle counts differ; masking may need improvement.");
        end
    endtask

    // CWE-1247: glitch resilience
    task check_glitch;
        begin
            rst = 1;
            @(posedge clk);
            rst = 0;

            run_round(8'hAA, 8'h5A);
            $display("[CWE-1247] Normal round, data_out = 0x%0h", data_out);

            rst = 1;
            @(posedge clk);
            rst = 0;

            inject_glitch();
            run_round(8'hAA, 8'h5A);

            $display("[CWE-1247] After glitch, data_out = 0x%0h", data_out);

            if (data_out == 8'h00)
                $display("[CWE-1247] PASS: glitch forces safe state.");
            else
                $display("[CWE-1247] FAIL: glitch not handled.");
        end
    endtask

    initial begin
        rst = 1;
        glitch_detect = 0;
        data_in = 0;
        mask_in = 0;
        @(posedge clk);
        rst = 0;

        check_scrub();
        check_side_channel();
        check_glitch();

        $display("Secure testbench completed.");
        $finish;
    end

endmodule
