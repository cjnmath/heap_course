## Unsafe unlinking

本文介绍一种对于`unsorted_bin`  的利用技巧，该技巧来自于本世纪初phrack杂志的[一篇文章](http://www.phrack.org/issues/57/9.html)。

虽然古老，但可以作为一个切入点，了解 glibc 早期版本防止heap 碎片化的做法，以及内存合并的规则。

这个利用的思想，对于现代版本的glibc同样适用(毕竟属于同一种malloc算法), 但需要做一些适配，后文save unlinking 会展开介绍。

### Unsorted bin机制

前面在介绍fastbin dup技巧时， 描述过fastbin机制，就是对于大小在0x20 - 0x80的内存块释放时， 会有对应的单向链表进行回收管理。

同样，对于大小在0x80以上的内存块（我们称之为unsorted bin）在释放的时候依然有链表进行管理，不过这次是双向链表。下面以

