// global-metadata.dat 的头部特征
var gDatPattern = "AF 1B B1 FA 18";
// dat的个数：多个全都需要dump出来
var gDatCount = 0;

// 输出日志
function out_log(msg) {
    if (msg) {
        console.log(msg);
    }
}

// 输出十六进制的消息
function out_hex(address) {
    out_log('\n找到了一块内存，地址是：' + address.toString());
    out_log(hexdump(address,
        {
            offset: 0,
            length: 0x110,
            header: true,
            ansi: true
        }
    ));
}

//get_self_process_name()获取当前运行进程包名，可能包名和进程名不一致
//参考：https://github.com/lasting-yang/frida_dump/blob/master/dump_dex_class.js
function get_self_process_name() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);
        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}

// 根据起始地址，加上偏移量，读取出内存上的数值
function read_int(startAdd, offset) {
    var definitions = parseInt(startAdd, 16) + offset;
    var result = Memory.readInt(ptr(definitions));
    return result;
}

// 文件结构中的size和count的区块偏移量，两个版本
function getMetaDataSize(address) {
    // 版本一：0x108，0x10C
    var Offset_size = read_int(address, 0x108);
    var Count_size = read_int(address, 0x10C);

    // 版本二：0x100，0x104
    if (Count_size < 10) {
        Offset_size = read_int(address, 0x100);
        Count_size = read_int(address, 0x104);
    }
    return Offset_size + Count_size;
}

// 根据基址和大小，从内存中dump出文件
function farm_dat(address, data_size) {
    var file_name = "/global-metadata.dat";
    if (gDatCount > 0) {
        file_name = file_name + gDatCount;
    }
    var dat_path = "/data/data/" + get_self_process_name() + file_name;
    // var file = new File(dat_path, "wb");
    // file.write(Memory.readByteArray(address, data_size));
    // file.flush();
    // file.close();
    out_log('导出一个文件：' + dat_path);
    gDatCount++;
}

// 对指定的内存块标记进行扫描
function scan_mem(section) {
    var sec_size = section.size;
    if (sec_size <= 0x1000) {
        // 内存段太小，就不可能是 data（不排除是跨内存段的，但概率很小）
        return;
    }
    Memory.scan(section.base, sec_size, gDatPattern,
        {
            onMatch: function (address, size) {
                out_hex(address);
                // 根据偏移算出global-metadata的文件大小
                var metadata_size = getMetaDataSize(address);
                out_log("模块大小：" + metadata_size);

                // 根据结果，进行dump
                farm_dat(address, metadata_size);
            },
            onComplete: function () {
                // out_log("搜索完毕");
            }
        }
    );
}

function frida_Memory() {
    Java.perform(function () {
        out_log("    文件头部标识为：" + gDatPattern);

        // 遍历当前进程中所有的可读内存段
        var sectionArr = Process.enumerateRanges("r--");
        var len = sectionArr.length;
        out_log("    可读内存段个数：" + len);
        for (var i = 0; i < len; i++) {
            var section = sectionArr[i];
            scan_mem(section);
        }
    });
}

// 需要包名运行起来后，才能正常运行；而且需要外界的包名参数
setImmediate(frida_Memory); 
