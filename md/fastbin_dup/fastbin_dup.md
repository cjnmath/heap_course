# fastbin dup

本文介绍一种叫**fastbin dup**的 heap 溢出利用技巧

本质上这是一种double free漏洞，通过double free改写数据链表指针，达到任意写的目的。

首先，我们先了解一下fastbin内存的管理机制：

### fastbin机制

众所周知，Linux系统下，调用`malloc`函数，libc库会动态地分配内存。

> 所谓“动态”， 就是指malloc的大小编译时未知，运行时才能知道，比如等待用户输入。这样，一个不可避免的问题是：大小不一的内存块，如何高效利用？为达到高效，要尽可能保持内存连片，要尽可能避免出现新调用的`malloc`在旧内存块里找不到合适大小的，或者即使能找到，但太大，又要分割，导致进一步的碎片化。
>
> 工程经验上来说，小块的内存申请的频率比较高，且造成碎片化的可能性很高，所以要引入链表的数据结构进行管理。

对于libc来说，小内存块(0x20 - 0xb0)都属于fastbin的范畴。下面以 [fastbin_demo](../../fastbin_dup/fastbin_demo) 为例，阐述fastbin大小的内存申请和释放的过程：

在gdb中加载 [fastbin_demo](../../fastbin_dup/fastbin_demo) ，在main函数打断点，逐行运行程序到下图位置：

![Screen Shot 2022-04-24 at 08.57.40](fastbin_dup.assets/Screen Shot 2022-04-24 at 08.57.40.png)

这时，已经运行了三行malloc代码，用命令`vis`查看当前heap的状态：

![Screen Shot 2022-04-24 at 09.01.12](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.01.12.png)

根据导论， 由上图可知总共有三个malloc_chunk，大小都是0x20。（这是64位系统`malloc`分配的最小大小，即使`malloc(0)`也会分配0x20）

用命令`fastbin`查看当前fastbin的状态：

![](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.02.50.png)

这个各个大小的fastbin都是空的（因为已经申请的还没释放）

然后，我们在执行下面的`free(a);`:

![Screen Shot 2022-04-24 at 09.05.20](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.05.20.png)

这时，再查看`vis`和`fastbin`

![Screen Shot 2022-04-24 at 09.06.56](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.06.56.png)

可见，heap无明显变化，0x20大小的fastbin指向了原来a指向的内存块（因为执行了`free(a)`）

接下来，再执行`free(b)`, 同样查看`vis`和`fastbin`:

![Screen Shot 2022-04-24 at 09.20.44](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.20.44.png)

这时heap的0x405030的位置写入了0x0000000000405000， （这恰恰是上一个chunk的位置）而0x20大小的fastbin则出现了链表表示。

查看源码，可知各个大小的fastbin其实就是释放出来的内存，他们之间通过单向链表的形式链接起来，每次释放一个这样大小的内存块，其地址都会被加入到这个链表里，所以就管理来说，只要我知道了这个单向链表的头，我就能找到这个链表的每一个内存块，不管你在哪个内存地址。

因此，系统只需记录头的位置即可，每次加入新块，系统更新该块的位置（作为头），同时在该块里写入之前的头（维持链表）

而这个头其实就是储存在main_arena里：

![Screen Shot 2022-04-24 at 09.40.19](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.40.19.png)

我们再运行一行代码：

![Screen Shot 2022-04-24 at 09.42.19](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.42.19.png)

内存变化符合之前描述。

这时，如果我们再需要一块0x20大小的内存块，比如再malloc一次：

![Screen Shot 2022-04-24 at 09.47.54](fastbin_dup.assets/Screen Shot 2022-04-24 at 09.47.54.png)

libc管理算法会优先从fastbin链表中查找对应大小的链表，如果非空，直接pop第一个出来(LIFO模式)，剩下的块再保持链表。从而无需再申请新的内存块，避免因内存里遍布小内存块，而导致的内存碎片化问题。

### double free



### 任意写













