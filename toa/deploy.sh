#!/bin/sh

make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules_install

mkdir -p /lib/modules/$(uname -r)/extra
cp -f toa.ko /lib/modules/$(uname -r)/extra/toa.ko 
cat > /etc/sysconfig/modules/toa.modules<<EOF
#!/bin/sh

/sbin/modinfo -F filename toa > /dev/null 2>&1
if [ \$? -eq 0 ]; then
    /sbin/modprobe toa
fi
EOF
chmod +x /etc/sysconfig/modules/toa.modules
