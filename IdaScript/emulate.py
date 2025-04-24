from unicorn import *
from unicorn.x86_const import *

import importlib
from typing import List, Tuple
from dataclasses import dataclass

class Emulator:
    """用于模拟执行基类
    存在一些公共方法
    """
    @dataclass
    class MemMap:
        """存放映射的内存信息
        """
        mem_start: int
        mem_size: int
        mem_end: int

    def __init__(self, arch, mode) -> None:
        """创建模拟执行引擎

        Args:
            arch : 模拟器架构x86
            mode : 模拟器模式32/64
        """   
        #private
        self.__m_uc = None
        self.__m_mems: List[Emulator.MemMap] = []   #所有mem_map的内存起始地址和内存大小 

        #protected
        self._m_arch = None
        self._m_mode = None

        self._m_arch = arch
        self._m_mode = mode
        self.__m_uc = Uc(arch, mode)
    
    def __del__(self):
        for mem_info in self.__m_mems:
            self.unmap_mem(mem_info.mem_start, mem_info.mem_size)
        #我也不知道映射的内存需不需要手动释放, Uc是不需要手动释放的
    
    def _is_arch32(self) -> bool:
        is32 = False
        if self._m_mode == UC_MODE_32:
            is32 = True
        return is32

    def __reg2uc(self, reg : str):
        """将reg名转为uc常量

        Args:
            reg : 寄存器名
        
        Returns:
            int : 失败返回None
        """
        attr_name = ""
        arch_name = ""
        module_name = "unicorn."
        reg_name = reg.upper()
        if (self._m_arch == UC_ARCH_X86):
            arch_name = "X86"
            module_name += "x86_const"
        attr_name = f"UC_{arch_name}_REG_{reg_name}"
        
        try:
            arch_const_module = importlib.import_module(module_name)
            return getattr(arch_const_module, attr_name)
        except (ModuleNotFoundError, AttributeError):
            return None
            
    def set_reg(self, reg : str, value = 0):
        reg_id = self.__reg2uc(reg)
        self.__m_uc.reg_write(reg_id, value)

    def get_reg(self, reg : str):
        reg_id = self.__reg2uc(reg)
        return self.__m_uc.reg_read(reg_id)

    def map_mem(self, addr:int, size: int) -> Tuple[int, int]:
        """映射内存

        Args:
            addr (int): 地址
            size (int): 大小

        Returns:
            Tuple[int, int]: (真正的地址, 真正的大小) 因为API要求是4k对齐的
        """
        #不是4k对齐的 则往前进行4k对齐 预留一段空间
        mem_4k_addr = (addr & ~(4095))
        mem_4k_num = ((size + addr - mem_4k_addr) // 4096) + 1 # mem要是4kb的倍数
        mem_4k_size = mem_4k_num * 4 * 1024
        mem_4k_end = mem_4k_addr + mem_4k_size

        new_mem = True
        for mem_info in self.__m_mems: #判断是否已经在mems中, 进行合并
            index = self.__m_mems.index(mem_info)
            if (mem_4k_addr >= mem_info.mem_start) and (mem_4k_end <= mem_info.mem_end):
                return mem_4k_addr, mem_4k_size #已经存在
            elif (mem_4k_addr <= mem_info.mem_start) and ((mem_4k_end >= mem_info.mem_start) and (mem_4k_end <= mem_info.mem_end)):
                new_size = mem_info.mem_size + (mem_info.mem_start - mem_4k_addr)
                self.__m_mems[index].mem_start = mem_4k_addr
                self.__m_mems[index].mem_size = new_size
                new_mem = False
                break
            elif ((mem_4k_addr >= mem_info.mem_start) and (mem_4k_addr <= mem_info.mem_end)) and (mem_4k_end >= mem_info.mem_end):
                new_size = mem_info.mem_size + (mem_4k_end - mem_info.mem_end)
                self.__m_mems[index].mem_end = mem_4k_end
                self.__m_mems[index].mem_size = new_size
                new_mem = False
                break
            elif (mem_4k_addr <= mem_info.mem_start) and (mem_4k_end >= mem_info.mem_end):
                self.__m_mems[index].mem_start = mem_4k_addr
                self.__m_mems[index].mem_size = mem_4k_size
                self.__m_mems[index].mem_end = mem_4k_end
                new_mem = False
                break

        self.__m_uc.mem_map(mem_4k_addr, mem_4k_size)

        if new_mem:
            mem_info = Emulator.MemMap(mem_start=mem_4k_addr, mem_size=mem_4k_size, mem_end=mem_4k_end)
            self.__m_mems.append(mem_info) #添加到__m_mems中
        return mem_4k_addr, mem_4k_size

    def unmap_mem(self, addr: int, size: int) -> bool:
        """取消内存映射

        Args:
            addr (int): 起始地址
            size (int): 大小 会自动4k对齐

        Returns:
            bool: 是否成功
        """
        mem_4k_addr = (addr & ~(4095))
        mem_4k_num = ((size + addr - mem_4k_addr) // 4096) + 1 # mem要是4kb的倍数
        mem_4k_size = mem_4k_num * 4 * 1024
        mem_4k_end = mem_4k_addr + mem_4k_size

        find_mem_info = None
        for mem_info in self.__m_mems:
            if (mem_4k_addr >= mem_info.mem_start) and (mem_4k_end <= mem_info.mem_end):
                find_mem_info = mem_info
                break
        if find_mem_info == None:
            return False
        else:
            if (mem_4k_addr == find_mem_info.mem_start) and (mem_4k_end == find_mem_info.mem_end):
                self.__m_mems.remove(find_mem_info)
            elif (mem_4k_addr > find_mem_info.mem_start) and (mem_4k_end < find_mem_info.mem_end):                
                block1_start = find_mem_info.mem_start
                block1_size = mem_4k_addr - find_mem_info.mem_start
                new_mem_block1 = Emulator.MemMap(mem_start=block1_start, mem_size=block1_size, mem_end=mem_4k_addr)
                block2_start = mem_4k_end
                block2_size = find_mem_info.mem_end - mem_4k_end
                new_mem_block2 = Emulator.MemMap(mem_start=block2_start, mem_size=block2_size, mem_end=find_mem_info.mem_end)
                self.__m_mems.remove(find_mem_info)
                self.__m_mems.append(new_mem_block1)
                self.__m_mems.append(new_mem_block2)

            self.__m_uc.mem_unmap(mem_4k_addr, mem_4k_size)
        return True

    def is_inmem(self, addr: int, size: int = 0) -> bool:
        """判断给定的内存块是否已经映射

        Args:
            addr (int): 地址
            size (int): 大小

        Returns:
            bool: 已经映射返回True
        """
        mem_start = addr
        mem_end = addr + size

        in_mem = False
        for mem_info in self.__m_mems:
            if (mem_start >= mem_info.mem_start) and (mem_end <= mem_info.mem_end):
                in_mem = True
                break
        return in_mem

    def write_mem(self, addr, wbytes) -> bool:
        """将bytes写入内存

        Args:
            addr : 要写入的地址
            wbytes : 要写入的数据
        
        Returns:
            bool: 是否成功
        """
        #print(f"[write_mem] addr:{hex(addr)} | byte_len:{len(bytes)}")
        
        if self.is_inmem(addr, len(wbytes)):
            self.__m_uc.mem_write(addr, wbytes)
            return True
        return False
    
    def read_mem(self, addr, size) -> bytes:
        """读取内存的值

        Args:
            addr : 地址
            size : 大小
        
        Returns:
            bytes: 读取的值
        """
        if self.is_inmem(addr, size):
           return self.__m_uc.mem_read(addr, size)
        return b''

    def add_hook(self, hook_type, func, usr_data = None):
        """添加一个钩子

        Args:
            hook_type : UC_HOOK_*
            func : 回调函数
            usr_data : 用户数据
        """
        self.__m_uc.hook_add(hook_type, func, usr_data)

    def start_emu(self, start_addr: int, end_addr: int) -> bool:
        """开始模拟执行

        Args:
            start_addr : 开始执行的地址(ip)
            end_addr : 结束地址

        Returns:
            bool: 是否开始成功
        """
        try:
            self.__m_uc.emu_start(start_addr, end_addr)
        except UcError as e:
            pc_id = None
            if (self._m_arch == UC_ARCH_X86):
                if (self._m_mode == UC_MODE_32):
                    pc_id = UC_X86_REG_EIP
                else:
                    pc_id = UC_X86_REG_RIP

            print(f"[Emu] ip: {hex(self.__m_uc.reg_read(pc_id))} | Emu Err: {e}")
            return False
        
        return True
    

class DestringEmulate(Emulator):
    def __init__(self) -> None:
        #protected
        self._m_code_size = 0       #机器码大小
        self._m_code_start = 0      #start是机器码起始地址
        self._m_stack_size = 0
        self._m_stack_base = 0

        #private
        self.__m_enc_data_addr = 0  #加密数据地址
        self.__m_dec_data_addr = 0  #解密后字符串放置地址
        super().__init__(UC_ARCH_X86, UC_MODE_64)
    
    def init_emu(self, code_addr, code_size):
        """初始化栈等信息

        Args:
            code_addr: 机器码开始地址
            code_size (int): 机器码大小.

        Returns:
            bool: 是否初始化成功
        """

        self._m_code_start = code_addr
        self._m_code_size = code_size
        self.map_mem(code_addr, code_size)

        #先写入nop
        nop_bytes = b'\x90' * code_size
        self.write_opcode(nop_bytes, code_addr)
        
        high_base = 0x0
        if self._m_mode == UC_MODE_64:
            high_base = 0xDE60000000
        self._m_stack_base = high_base + 0x11B0000
        self._m_stack_size = 1 * 1024 * 1024 #1MB
        self.map_mem(self._m_stack_base, self._m_stack_size)

        # 离栈底预留0x100的空间
        sp = self._m_stack_base + self._m_stack_size - 0x100
        bp = sp
        #if self._is_arch32() :
        sp -= 0x100 #32位下的栈帧结构 再把sp往上提 预留变量的空间

        if self._m_arch == UC_ARCH_X86:
            if self._m_mode == UC_MODE_32:
                super().set_reg('ebp', bp)
                super().set_reg('esp', sp)
            elif self._m_mode == UC_MODE_64:
                super().set_reg('rsp', sp)
                super().set_reg('rbp', bp)
                #因为编译优化的问题, 可能两个片段共用同一个mul r8中的r8, mov r8, 0CCCCCCCCCCCCCCCDh
                #而一个片段会用到的乘法寄存器可能为r8,r9,rdi,rsi 因此直接先初始化
                super().set_reg('r8', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r9', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r10', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r11', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r12', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r13', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r14', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('r15', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('rdi', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('rsi', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('rbx', 0xCCCCCCCCCCCCCCCD)
                super().set_reg('rdx', 0xCCCCCCCCCCCCCCCD)
        return True

    def write_opcode(self, opcodes:bytes, addr:int = None) -> bool:
        """写入机器码到地址处

        Args:
            opcodes (bytes): 机器码
            addr (int, optional): 如果为None则从起始地址开始写. Defaults to None.

        Returns:
            bool: 是否成功
        """
        write_addr = self._m_code_start if addr == None else addr
        if not super().is_inmem(write_addr, len(opcodes)): #要写的地址
            super().map_mem(write_addr, len(opcodes))
        return super().write_mem(write_addr, opcodes)
    
    def write_enc_data(self, data_addr:int, data_bytes:bytes):
        self.__m_enc_data_addr = data_addr
        self.map_mem(data_addr, len(data_bytes))
        return super().write_mem(data_addr, data_bytes)

    def init_dec_data(self, data_addr:int):
        self.__m_dec_data_addr = data_addr
        self.map_mem(data_addr, 512) #直接分配512字节的空间
        return super().write_mem(data_addr, b'\x00' * 512)
    
    def init_dec_enc_reg(self, enc_reg:str, dec_reg:str) -> bool:
        enc_data_addr = self.__m_enc_data_addr
        dec_data_addr = self.__m_dec_data_addr
        if (enc_data_addr == 0) or (dec_data_addr == 0):
            return False
        super().set_reg(enc_reg, self.__m_enc_data_addr)
        super().set_reg(dec_reg, self.__m_dec_data_addr)
    
    def read_dec_string(self, size:int = None) -> str:
        dec_data_addr = self.__m_dec_data_addr
        if dec_data_addr == 0:
            return "" #未设置解密存放地址
        
        all_bytes = b'' #全部的字节
        if size == None:
            one_byte = super().read_mem(dec_data_addr, 1)
            while one_byte != b'\x00':
                all_bytes += one_byte
                one_byte = super().read_mem(dec_data_addr, 1)
        else:
            all_bytes = super().read_mem(dec_data_addr, size)
        
        all_bytes = all_bytes[:-1] if all_bytes[-1] == 0 else all_bytes #去掉末尾的\x00 
        return all_bytes.decode(encoding='utf-8')

    def reg_value(self, reg, value = None):
        """设置/获取 寄存器的值

        Args:
            reg : 寄存器
            value (optional): 当此值为None时则获取寄存器值. Defaults to None.
        """
        ret_value = 0
        if value == None:
            ret_value = super().get_reg(reg)
        else:
            super().set_reg(reg, value)
        return ret_value

    def stack_value(self, reg, offset, size = None, value = None):
        """设置/获取 栈值

        Args:
            reg : 寄存器
            offset : 偏移
            size : 写入大小 4或者8 为None则按当前架构大小
            value (optional): 当此值为None时则获取栈值. Defaults to None.
        """
        ret_value = None
        rw_addr = super().get_reg(reg) + offset

        rw_size = size #自动识别size
        if rw_size is None:
            rw_size = 4 if super()._is_arch32() else 8

        if (value is not None): #写入
            value_bytes = value.to_bytes(16, 'little', signed=True) #先转到16个字节再截取rw_size个字节
            super().write_mem(rw_addr, value_bytes[:rw_size])
        else: #读取
            read_bytes = super().read_mem(rw_addr, rw_size)
            if (len(read_bytes) == rw_size):
                ret_value = int.from_bytes(read_bytes, byteorder='little', signed=True)
        return ret_value

    def add_code_hook(self, func, usr_data = None):
        """添加代码钩子

        Args:
            func: 回调函数
            usr_data (optional): 用户数据. Defaults to None.
        """
        super().add_hook(UC_HOOK_CODE, func, usr_data)
    
    def start_dec_emu(self, start_addr: int, end_addr = None) -> bool:
        """开始模拟执行

        Args:
            start_addr : 开始执行的地址(ip)
            end_addr : 结束地址如果为None则一直执行到函数末

        Returns:
            bool: 是否开始成功
        """
        until_addr = None

        code_begin = self._m_code_start
        code_end = self._m_code_start + self._m_code_size
        if end_addr == None:
            until_addr = code_end
        else:
            until_addr = end_addr
        return super().start_emu(start_addr, until_addr)