module Ex1 (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        reg_wen,
    input  wire        reg_ren,
    input  wire [2:0]  reg_addr,
    input  wire [31:0] reg_wdata,
    output reg  [31:0] reg_rdata,

    input  wire [1:0]  cpu_privilege_level,
    input  wire        user_mode,

    output wire [31:0] crypto_key,
    output wire [31:0] security_config
);

    reg [31:0] security_config_reg;
    reg [31:0] crypto_key_reg;
    reg [31:0] status_reg;
    reg [31:0] version_reg;

    assign security_config = security_config_reg;
    assign crypto_key      = crypto_key_reg;

    wire priv_ok = 1'b1; 

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            security_config_reg <= 32'hA5A5_0001;
            crypto_key_reg      <= 32'hDEAD_BEEF;
            status_reg          <= 32'h0000_0000;
            version_reg         <= 32'h0000_0100;
            reg_rdata           <= 32'h0;
        end else begin
            if (reg_wen) begin
                case (reg_addr)
                    3'h0: if (priv_ok) security_config_reg <= reg_wdata; 
                    3'h1: if (priv_ok) crypto_key_reg      <= reg_wdata;
                    3'h2: status_reg <= reg_wdata;
                    default: ;
                endcase
            end

            if (reg_ren) begin
                case (reg_addr)
                    3'h0: reg_rdata <= (priv_ok) ? security_config_reg : 32'hDEAD_DEAD; 
                    3'h1: reg_rdata <= (priv_ok) ? crypto_key_reg      : 32'hDEAD_DEAD; 
                    3'h2: reg_rdata <= status_reg;
                    3'h3: reg_rdata <= version_reg;
                    default: reg_rdata <= 32'hDEAD_DEAD;
                endcase
            end
        end
    end

endmodule
