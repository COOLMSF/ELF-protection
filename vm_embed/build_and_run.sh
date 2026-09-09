cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wl,-z,relro,-z,now \
  vm_embedded_stub.c -o vm_embedded_stub -lcrypto

cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  vm_embed_packer.c -o vm_embed_packer -lcrypto


export VM_PACKER_PASSWORD='long-random-secret'

./vm_embed_packer \
  ./vm_embedded_stub \
  ./helloworld \
  ./helloworld.protected

