## Unsafe unlinking

本文介绍一种对于`unsorted_bin`  的利用技巧，该技巧来自于本世纪初phrack杂志的[一篇文章](http://www.phrack.org/issues/57/9.html)。

虽然古老，但可以作为一个切入点，了解 glibc 早期版本防止heap 碎片化的做法，以及内存合并的规则。

这个利用的思想，对于现代版本的glibc同样适用(毕竟属于同一种malloc算法), 但需要做一些适配，后文safe unlinking 会展开介绍。

### Unsorted bin机制

前面在介绍fastbin dup技巧时， 描述过fastbin机制，就是对于大小在0x20 - 0x80的内存块释放时， 会有对应的单向链表进行回收管理。

同样，对于大小在0x80以上的内存块（我们称之为unsorted bin）在释放的时候依然有链表进行管理，不过这次是双向链表。

下面以demo1为例， 调试观察内存变化：

在gdb中加载 demo1， 在main函数打断点，逐步运行到以下位置：

![2022-08-04_18-16-27](unsafe_unlinking.assets/2022-08-04_18-16-27.png)

这时候，heap是这个样子：

![2022-08-04_18-17-45](unsafe_unlinking.assets/2022-08-04_18-17-45.png)

执行`free(a);`后：

![vis_heap](unsafe_unlinking.assets/vis_heap.png)

留意到0x20大小的chunk的PRE_INUSE flag被设为0，表示前一个chunk被释放，处于非占用的状态。它前面8个字节也被写入了前一个chunk的大小（即0x90， 这时这8个字节其实可以算作0x20chunk的了，这点很容易迷惑人）

前一个chunk的内部也被写入了两个指向main_arena的指针。

再执行`free(b);`后：

![rect2085](unsafe_unlinking.assets/rect2085.png)

由于0x90的chunk不在fastbin的大小范围，其属于所谓unsorted_bin, 用命令`unsortedbin`可查看基本的节点结构：

![2022-08-05_10-24-01](unsafe_unlinking.assets/2022-08-05_10-24-01.png)

注意其中那个地址0x7ffff7dd4b78其实是在main_arena 里的，我们查看一下main_arena的样子：

![2022-08-05_10-35-16](unsafe_unlinking.assets/2022-08-05_10-35-16.png)

综上调试的现象，我们有以下结论：

> 1. 0x90大小的chunk释放后，会被加入到一个叫unsorted_bin的链表。
> 2. unsorted_bin是个双向环状链表，链表的"头"在main_arena 。

![unsorted_bins](unsafe_unlinking.assets/unsorted_bins.png)

### 内存合并 和 unlinking 

前面例子里的a、b chunk都有fastbin chunk阻隔，如果去掉这些阻隔呢？

以demo2为例子，观察合并内存变化：

在gdb中加载 demo2， 在main函数打断点，逐步运行到以下位置：

![2022-08-05_12-14-15](unsafe_unlinking.assets/2022-08-05_12-14-15.png)

这时，heap的样子如下：

![2022-08-05_12-15-14](unsafe_unlinking.assets/2022-08-05_12-15-14.png)

执行`free(d);`后，变成这样：

![2022-08-05_12-17-11](unsafe_unlinking.assets/2022-08-05_12-17-11.png)

可见，原来的 d chunk消失了，算一下top chunk大小和位置变化，可知 d chunk被并入了top chunk。

查一下unsorted_bin,发现 d chunk 在上面也没有记录

![2022-08-05_12-21-42](unsafe_unlinking.assets/2022-08-05_12-21-42.png)

由此可知，当一个unsorted bin 大小的chunk释放的时候，libc会检查这个chunk 附近的内存，看是否能合并，如果能，那就合并，否则才在unsorted bin的链表里做记录。这是一种防止内存碎片化的举措。

chunk d 和 top chunk 和并，是因为它们相邻，如果有阻隔自然就不会有合并了，但如果chunk d 前面的chunk 空闲且在unsorted bin 的记录中呢？ 我们继续调试：

重新申请chunk d, 添加大小为0x20的fastbin chunk作为阻隔， 再释放chunk c:

![2022-08-05_13-48-22](unsafe_unlinking.assets/2022-08-05_13-48-22.png)

释放chunk c 后，heap如下：

![image3140](unsafe_unlinking.assets/image3140.png)

被释放的chunk c 被unsorted bin记录， 且在chunk d 前。

这时如果再释放chunk d， 前面说过，这样必然有合并，但前面的chunk c 已经在unsorted bin的双向链表的记录里，如何处理呢？ 一个很自然的想法是，双向链表解除chunk c 这个节点，让chunk c 和 chunk d 合并，再把合并后的chunk 加回到原来的unsorted bin里：

![text4351](unsafe_unlinking.assets/text4351.png)

这个解除chunk c的过程就是所谓的**unlink**, 在早期版本的libc中（如v2.23）， 这个过程是以宏函数存在的, 逻辑如下：

![2022-08-05_14-23-58](unsafe_unlinking.assets/2022-08-05_14-23-58.png)

上面的P是需要解除的节点，unlink的核心逻辑是这段：

```c
FD = P->fd;
BK = P->bk;
FD->bk = BK;
BK->fd = FD;
```

注意这些都是宏代码，没有任何的强制检测，（所以被叫做unsafe unlink）假如P这个节点里的内容我能控制，（比如有某种溢出或者UAF）那么FD和BK的值我能控制，而`FD->bk = BK;`  意味着我能往一个我指定的地址里写入内容，这是任意写。（注意这是 一个双向的写，毕竟后面还有`BK->fd = FD;`，这给利用带来一定麻烦，因为地址`FD->bk`和`BK->fd `不一定同时可写， 当然在2000年初，那时候还没有NX措施，双向写可以都在heap上，且heap可执行，即可以注入shellcode） 

下面用一个例子说明这样的漏洞的利用：

### unsafe unlink

