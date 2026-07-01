


data_out = (grant_access) ? data_in : data_out;
grant_access = (usr_id == 3'h4) ? 1'b1 : 1'b0;

always @ (posedge clk or negedge rst_n)
begin
    if (!rst_n)
        data_out = 0;
    else
        data_out = (grant_access) ? data_in : data_out;
        grant_access = (usr_id == 3'h4) ? 1'b1 : 1'b0;
end