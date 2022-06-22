all: sgx_sign

linux-sgx-sign/:
	git submodule update --init $@

linux-sgx-sign/.PATCHED: linux-sgx-sign.patch | linux-sgx-sign/
	git -C linux-sgx-sign/ apply --intent-to-add "../$<"
	touch "$@"

linux-sgx-sign/sdk/sign_tool/SignTool/sgx_sign: linux-sgx-sign/.PATCHED
	$(MAKE) -C linux-sgx-sign/sdk/sign_tool/SignTool/ DEBUG=1 "CXXFLAGS=-DSE_SIM=1 -I../../../common/inc/internal/ -I../../../common/inc/ -I../../../psw/urts/ -g" CFLAGS=-g

sgx_sign: linux-sgx-sign/sdk/sign_tool/SignTool/sgx_sign
	ln -rsfn linux-sgx-sign/sdk/sign_tool/SignTool/sgx_sign ./

clean:
	$(RM) -r linux-sgx-sign/ sgx_sign

.PHONY:
sgx_sign_rebuild:
	$(MAKE) -C linux-sgx-sign/sdk/sign_tool/SignTool/ DEBUG=1 "CXXFLAGS=-DSE_SIM=1 -I../../../common/inc/internal/ -I../../../common/inc/ -I../../../psw/urts/ -g" CFLAGS=-g clean
	$(MAKE) sgx_sign
