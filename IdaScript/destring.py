import logging
import datetime
from typing import Tuple, List, Callable
from dataclasses import dataclass, field

#模拟执行
from emulate import DestringEmulate

#配置log
cur_log_level = logging.DEBUG #设置当前日志等级
cur_date = datetime.datetime.now().strftime("%Y%m%d") #当前日期
log_file_name = f"{cur_date}-weixin.log" #输出到的文件名
log_format = logging.Formatter('[wxd] %(asctime)s [%(levelname)s]\t %(message)s', datefmt="%Y-%m-%d %H:%M:%S") #日志格式 时间只到秒
logger = logging.getLogger('wx_script') #获取log
logger.setLevel(cur_log_level)  
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG) #控制台输出级别
console_handler.setFormatter(log_format)
logger.addHandler(console_handler) #配置输出到控制台
if cur_log_level != logging.DEBUG: 
    file_handler = logging.FileHandler(log_file_name)
    file_handler.setLevel(logging.INFO) #文件不输出DEBUG信息
    file_handler.setFormatter(file_handler)
    logger.addHandler(file_handler) #当前等级为Debug时不输出到文件中

import idc
import idautils
import ida_funcs
import ida_bytes
import ida_kernwin

def __quick_unload_script():
    """全局卸载函数 qscript指定的
    """
    global logger
    for handler in logger.handlers[:]: # 清除所有的处理器
        logger.removeHandler(handler)
    print("[wxd] Remove logger handler")

    global ACTION_NAME_0
    global ACTION_NAME_1
    if ida_kernwin.unregister_action(ACTION_NAME_0):
        print("[wxd] Unregistered action \"%s\"" % ACTION_NAME_0)
    if ida_kernwin.unregister_action(ACTION_NAME_1):
        print("[wxd] Unregistered action \"%s\"" % ACTION_NAME_1)

@dataclass
class DeAsmInfo:
    """解密字符串信息"""
    insns:List[int] = field(default_factory=list)   #所有涉及到的汇编指令的地址
    extra_info:dict = field(default_factory=dict)   #额外信息 比如{'cmp1': index, ...} index为在insns中的下标
    dec_str:str = ""                                #解密完的字符串

def get_find_sig() -> Callable[[list, int, DeAsmInfo], Tuple[bool, int]]:
    def convert_to_x64_register(reg_name):
        # 处理x86寄存器, 去掉 `e` 前缀并转换为对应的x64寄存器
        x86_to_x64 = {
            'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx',
            'esp': 'rsp', 'ebp': 'rbp', 'esi': 'rsi', 'edi': 'rdi',
            'ax': 'rax', 'cx': 'rcx', 'dx': 'rdx', 'bx': 'rbx',
            'sp': 'rsp', 'bp': 'rbp', 'si': 'rsi', 'di': 'rdi'
        }
        
        # 如果寄存器已经是x64寄存器, 直接返回
        if reg_name in ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 
                        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            return reg_name
        
        # 如果是带有 `d` 后缀的寄存器(如 r8d -> r8), 去掉 `d` 后缀
        if reg_name.endswith('d'):
            return reg_name[:-1]  # 去掉 `d` 后缀

        # 否则, 使用字典将x86寄存器转换为x64寄存器
        return x86_to_x64.get(reg_name, reg_name)

    def find_common_sig(eas:list, begin_index:int, de_info:DeAsmInfo) -> int:
        """获取两种解密逻辑的共同信息

        Args:
            eas (list): 汇编指令list
            begin_index (int): 开始寻找的index
            de_info (DeAsmInfo): 解密字符串信息

        Returns:
            int: 下一个寻找的index
        """
        if (begin_index >= len(eas)): 
            return -1 #超过了size
        
        cur_asm_insns = []  #涉及到的汇编指令
        cur_extra_info = {} #额外的地址信息

        cur_ea = eas[begin_index] #当前指令地址
        if (idc.print_insn_mnem(cur_ea) != 'cmp') or (idc.print_operand(cur_ea, 1) != '0'): #cmp *, 0
            return begin_index + 1 #当前指令不是cmp *, 0; 直接寻找下一个
        
        cmp0_value = -1 #具体的值
        cmp0_value_str = idc.print_operand(cur_ea, 0)
        if cmp0_value_str.startswith("cs:"):
            cmp0_value_str = cmp0_value_str[3:]
        cmp0_value = idc.get_name_ea_simple(cmp0_value_str)
        if cmp0_value == idc.BADADDR:
            return begin_index + 1 #没识别到操作数
    
        cur_extra_info['cmp0'] = begin_index - begin_index #第一个cmp指令index
        cur_extra_info['cmp0_value'] = cmp0_value #第一个cmp指令的第一个操作数
        cur_asm_insns.append(cur_ea) #添加涉及到的指令

        # [容错]继续找之后5条指令之内有没有jnz *;
        jnz_index = -1 #jnz指令的index
        max_after_index = 6 if (begin_index + 5) < len(eas) else (len(eas) - begin_index)
        for after_index in range(1, max_after_index):
            cur_tokens = idc.GetDisasm(eas[begin_index + after_index]).split()
            if len(cur_tokens) == 3:
                if (cur_tokens[0] == 'cmp') and ('byte_' in cur_tokens[1]) and (cur_tokens[2] == '0'):
                    return begin_index + 1#发现了另一个cmp

            jnz_mnem = idc.print_insn_mnem(eas[begin_index + after_index])
            if jnz_mnem == 'jnz': #找到了jnz指令
                jnz_index = begin_index + after_index
                break
        if jnz_index == -1:
            return begin_index + 1 #没找到jnz
        cur_extra_info['jnz1'] = jnz_index - begin_index
        cur_asm_insns.extend([eas[i] for i in range(begin_index + 1, jnz_index + 1)])
        
        # [容错]判断jnz下5条指令内是否有xor
        xor_index = -1  #xor指令的index
        xor_reg = ''    #xor指令的寄存器 
        max_after_index = 6 if (jnz_index + 5) < len(eas) else (len(eas) - jnz_index)
        for after_index in range(1, max_after_index):
            xor_addr = eas[jnz_index + after_index]
            if idc.print_insn_mnem(xor_addr) == 'xor':
                op1 = idc.print_operand(xor_addr, 0)
                op2 = idc.print_operand(xor_addr, 1)
                if op1 == op2: #特征正确
                    xor_index = jnz_index + after_index
                    xor_reg = op1 #xor寄存器
                    break
        if xor_index == -1:
            return begin_index + 1 #没找到xor
        cur_extra_info['xor'] = xor_index - begin_index
        cur_extra_info['xor_reg'] = xor_reg
        cur_asm_insns.extend([eas[i] for i in range(jnz_index + 1, xor_index + 1)])

        # [容错]判断xor之后5条指令是否有两个lea
        lea_enc_data_index, lea_dec_data_index, enc_data_addr, dec_data_addr = -1, -1, -1, -1
        max_after_index = 6 if (xor_index + 5) < len(eas) else (len(eas) - xor_index - 1)
        for after_index in range(1, max_after_index):
            lea1_addr = eas[xor_index + after_index]
            lea2_addr = eas[xor_index + after_index + 1]
            lea1_mnem = idc.print_insn_mnem(lea1_addr)
            lea2_mnem = idc.print_insn_mnem(lea2_addr)
            if (lea1_mnem == 'lea') and (lea2_mnem == 'lea'):
                lea1_op2 = idc.print_operand(lea1_addr, 1)
                lea2_op2 = idc.print_operand(lea2_addr, 1)
                #判断哪个是enc数据, 哪个是dec放置地址
                lea1_op2_addr = idc.get_name_ea_simple(lea1_op2)
                lea2_op2_addr = idc.get_name_ea_simple(lea2_op2)
                if (lea1_op2_addr == idc.BADADDR) or (lea2_op2_addr == idc.BADADDR):
                    continue  #不是需要的lea
                data_size = idc.get_item_size(enc_data_addr)
                if (data_size == 1) or (data_size > 200): #通过大小判断哪个是加密数据存放地址
                    enc_data_addr = lea1_op2_addr   #加密数据的地址
                    dec_data_addr = lea2_op2_addr   #解密字符串放置的地址
                    lea_enc_data_index = xor_index + after_index
                    lea_dec_data_index = xor_index + after_index + 1
                else:
                    enc_data_addr = lea2_op2_addr 
                    dec_data_addr = lea1_op2_addr
                    lea_enc_data_index = xor_index + after_index +1
                    lea_dec_data_index = xor_index + after_index
                break
        if (lea_enc_data_index == -1) or (lea_dec_data_index == -1):
            #如果找到了前三个特征 却没有找到lea enc和lea dec, 很有可能是编译优化导致这两个指令提前了
            # 没有想到很好的办法应对这种情况 如果能知道IDA右键菜单'Print register value'对应的API是哪个就好办了
            logger.warning("[{:#x}] maybe optimize situation...".format(eas[begin_index]))
            return begin_index + 1
        
        cur_extra_info['enc_data'] = enc_data_addr
        cur_extra_info['dec_data'] = dec_data_addr
        cur_extra_info['lea_enc'] = lea_enc_data_index - begin_index
        cur_extra_info['lea_dec'] = lea_dec_data_index - begin_index
        cur_asm_insns.extend([eas[i] for i in range(xor_index + 1, lea_dec_data_index + 1)])

        de_info.insns = cur_asm_insns #直接赋值 因为是首先寻找的
        de_info.extra_info = cur_extra_info
        return lea_dec_data_index + 1

    def try_find_sig1(eas:list, begin_index:int, de_info:DeAsmInfo) -> Tuple[bool, int]:
        """尝试获取解密特征1的信息

        Args:
            eas (list): 汇编指令list
            begin_index (int): 开始寻找的index
            de_info (DeAsmInfo): 解密字符串信息

        Returns:
            tuple: (是否找到了特征1, 下一个寻找的index)
        """
        if (begin_index >= len(eas)): 
            return -1 #超过了size

        # 找到了(cmp *, 0) + (jnz *) + (xor reg, reg) + (lea *, enc) + (lea *, dec)
        # 继续找(cmp reg, value) + (jnz *) + (mov *, 1)  
        dec_str_len = -1 #解密后的字符串长度 因为两种解密都是+2 所以长度为cmp reg, value中的value/2
        cmp_reg_index, jnz2_index, mov1_index = -1, -1, -1
        cmp_reg_r = convert_to_x64_register(de_info.extra_info['xor_reg']) # eax -> rax
        max_after_index = 31 if (begin_index + 30) < len(eas) else (len(eas) - begin_index)
        for after_index in range(5, max_after_index): #从后5-30中条指令中找
            cur_ea = eas[begin_index + after_index]
            if (idc.print_insn_mnem(cur_ea) != 'cmp') or (idc.print_operand(cur_ea, 0) != cmp_reg_r): #不是cmp reg, value
                continue #寻找下一个

            cmp_op2_str = idc.print_operand(cur_ea, 1) #去掉末尾的h 
            cmp_op2_str = cmp_op2_str[:-1] if cmp_op2_str.endswith('h') else cmp_op2_str
            if (len(cmp_op2_str) <= 0) or (cmp_op2_str[0] in ['r', 'e', '[']):
                continue #如果是r或者e打头的说明是寄存器
            dec_str_len = int(cmp_op2_str, 16) #转为数值

            cmp_reg_index = begin_index + after_index
            cur_ea = eas[cmp_reg_index + 1] #判断cmp下一个是否为jnz
            if idc.print_insn_mnem(cur_ea) != 'jnz':
                continue

            jnz2_index = cmp_reg_index + 1
            cur_ea = eas[jnz2_index + 1] #判断jnz下一个是否为mov *, 1;
            if (idc.print_insn_mnem(cur_ea) == 'mov') and (idc.print_operand(cur_ea, 1) == '1'):#继续判断后一个指令是否为mov *, 1
                mov1_value = -1
                mov1_value_str = idc.print_operand(cur_ea, 0) #判断mov操作数是否为最开始cmp value, 0的操作数
                if mov1_value_str.startswith("cs:"):
                    mov1_value_str = mov1_value_str[3:]
                mov1_value = idc.get_name_ea_simple(mov1_value_str)
                if mov1_value == de_info.extra_info['cmp0_value']:
                    mov1_index = jnz2_index + 1
                    break
        if mov1_index != -1: #找到了特征1
            de_info.extra_info['dec_str_len'] = dec_str_len
            de_info.extra_info['cmp_len'] = len(de_info.insns) + cmp_reg_index - begin_index
            de_info.extra_info['jnz2'] = len(de_info.insns) + jnz2_index - begin_index
            de_info.extra_info['mov1'] = len(de_info.insns) + mov1_index - begin_index
            de_info.insns.extend([eas[i] for i in range(begin_index, mov1_index + 1)])
            de_info.extra_info['sig'] = 'sig1' #标志sig1
            return (True, mov1_index + 1)

        return (False, begin_index + 1)

    def try_find_sig2(eas:list, begin_index:int, de_info:DeAsmInfo) -> Tuple[bool, int]:
        if (begin_index >= len(eas)): 
            return -1 #超过了size

        # 继续找(cmp reg, value) + (jz *) + (mov *, 1) + (jmp *)
        dec_str_len = -1 #解密后的字符串长度 因为两种解密都是+2 所以长度为cmp reg, value中的value/2
        cmp_reg_index, jz_index, jmp_index = -1, -1, -1
        cmp_reg_r = convert_to_x64_register(de_info.extra_info['xor_reg']) # r8d -> r8
        max_after_index = 16 if (begin_index + 15) < len(eas) else (len(eas) - begin_index)
        for after_index in range(2, max_after_index): #从后2-15中条指令中找
            cur_ea = eas[begin_index + after_index]
            if (idc.print_insn_mnem(cur_ea) != 'cmp') or (idc.print_operand(cur_ea, 0) != cmp_reg_r): #不是cmp reg, value
                continue #寻找下一个

            cmp_op2_str = idc.print_operand(cur_ea, 1) #去掉末尾的h 
            cmp_op2_str = cmp_op2_str[:-1] if cmp_op2_str.endswith('h') else cmp_op2_str
            if (len(cmp_op2_str) <= 0) or (cmp_op2_str[0] in ['r', 'e', '[']):
                continue #如果是r或者e打头的说明是寄存器
            dec_str_len = int(cmp_op2_str, 16) #转为数值

            cmp_reg_index = begin_index + after_index
            cur_ea = eas[cmp_reg_index + 1] #判断cmp下一个是否为jz
            if idc.print_insn_mnem(cur_ea) != 'jz':
                continue

            jz_index = cmp_reg_index + 1
            #判断jz跳转到的地址处的指令是否为mov value, 1;
            jz_jmp_ea = -1
            jz_value_str = idc.print_operand(cur_ea, 0)
            if jz_value_str.startswith("loc_"):
                jz_value_str = jz_value_str[4:]
            jz_jmp_ea = int(jz_value_str, 16)
            if (idc.print_insn_mnem(jz_jmp_ea) == 'mov') and (idc.print_operand(jz_jmp_ea, 1) == '1'):
                mov1_value = -1
                mov1_value_str = idc.print_operand(jz_jmp_ea, 0) #判断mov操作数是否为最开始cmp value, 0的操作数
                if mov1_value_str.startswith("cs:"):
                    mov1_value_str = mov1_value_str[3:]
                mov1_value = idc.get_name_ea_simple(mov1_value_str)
                if mov1_value != de_info.extra_info['cmp0_value']:
                    continue
            
            #找到jmp结束标志
            for after_jz_index in range(2, 11): #从后2-10中条指令中找
                cur_jmp_ea = eas[jz_index + after_jz_index]
                if idc.print_insn_mnem(cur_jmp_ea) == 'jmp':
                    jmp_index = jz_index + after_jz_index
                    break
            if jmp_index != -1: #找到了特征2
                break
        
        if jmp_index != -1: #找到了特征2
            de_info.extra_info['dec_str_len'] = dec_str_len
            de_info.extra_info['cmp_len'] = len(de_info.insns) + cmp_reg_index - begin_index
            de_info.extra_info['jz'] = len(de_info.insns) + jz_index - begin_index
            de_info.extra_info['jmp'] = len(de_info.insns) + jmp_index - begin_index
            de_info.insns.extend([eas[i] for i in range(begin_index, jmp_index + 1)])
            de_info.insns.append(jz_jmp_ea)
            de_info.extra_info['mov1'] = len(de_info.insns) - 1#mov1放在末尾 
            de_info.extra_info['sig'] = 'sig2' #标志sig2
            return (True, jmp_index + 1)

        return (False, begin_index + 1)

    def find_sig(eas:list, begin_index:int, de_info:DeAsmInfo) -> Tuple[bool, int]:
        """获取解密逻辑信息

        Args:
            eas (list): 汇编指令list
            begin_index (int): 开始寻找的index
            de_info (DeAsmInfo): 解密字符串信息

        Returns:
            tuple: (是否寻找到, 错误码或下一个寻找的index)
        """
        if (begin_index >= len(eas)): 
            return (False, -1) #超过了size
                
        next_index = find_common_sig(eas, begin_index, de_info)
        if next_index <= begin_index + 1:
            return (False, next_index) #说明没找到
        
        is_sig1, sig1_index = try_find_sig1(eas, next_index, de_info)
        if is_sig1:
            return (True, sig1_index)
        is_sig2, sig2_next = try_find_sig2(eas, next_index, de_info)
        if is_sig2:
            return (True, sig2_next)
        return (False, -2) #找到了开始特征, 没找到结束特征
    
    return find_sig


def get_destring_info(func_t):
    """获取解密字符串逻辑信息
    """
    find_sig_func = get_find_sig()

    #当前函数的指令heads
    fstart_addr = func_t.start_ea
    fend_addr = func_t.end_ea
    each_eas = list(idautils.Heads(fstart_addr, fend_addr)) #gen转list

    prob_destring_infos:List[DeAsmInfo] = [] #可能的解密汇编片段信息

    next_index = 0 #当前指令的index
    while True:
        cur_de_info = DeAsmInfo()
        find_ok, next_index = find_sig_func(each_eas, next_index, cur_de_info)
        if find_ok:
            prob_destring_infos.append(cur_de_info)
            logger.debug("[" + hex(cur_de_info.insns[0]) + "] " + str(cur_de_info))
        else:
            if next_index == -1:
                #logger.debug("reach max index")
                break
            elif next_index == -2: #只找到了开始特征
                logger.error("[{}] can't find end sig!".format(hex(cur_de_info.insns[0])))            
                break

    logger.info("[{}] search over!... find [{}] fragments".format(hex(fstart_addr), str(len(prob_destring_infos))))
    return prob_destring_infos
    
def emu_destring_logic(de_info:DeAsmInfo) -> str:
    """模拟执行解密逻辑

    Args:
        de_infos (DeAsmInfo): 解密片段信息
    
    Returns:
        str: 解密后的字符串
    """
    def get_emu_opcodes(sig_info:DeAsmInfo) -> dict:
        """获取模拟执行的字节码(nop掉一些)

        Args:
            sig_info (dict): 特征信息 {'cmp':addr, ...}

        Returns:
            dict: {地址:字节}
        """
        nop_addrs = None #需要nop掉的地址
        nop_index = [sig_info.extra_info['cmp0'], sig_info.extra_info['jnz1'], sig_info.extra_info['mov1']] #无论是sig1还是sig2都是这3个
        nop_addrs = [sig_info.insns[index] for index in nop_index]

        addr_op_dict = {}
        for item_addr in sig_info.insns:
            cur_insn_size = idc.get_item_size(item_addr)
            if item_addr in nop_addrs:
                addr_op_dict[item_addr] = (b'\x90' * cur_insn_size)
            else:
                insn_bytes = idc.get_bytes(item_addr, cur_insn_size)
                addr_op_dict[item_addr] = insn_bytes
        return addr_op_dict
    
    def get_enc_data(enc_data_addr:int, data_size:int = None) -> bytes:
        """读取加密的数据

        Args:
            enc_data_addr (int): 加密数据地址
            data_size (int): 读取的size. 为None自动推算

        Returns:
            bytes: 数据
        """
        read_size = data_size if data_size != None else idc.get_item_size(enc_data_addr)
        if (read_size == 1) or (read_size < 100): #说明该符号并未被IDA识别为数组
            #一个加密数据的数组, 一般是以多个0作为结尾. 或者找到下一个符号处也可
            next_head_addr = idc.next_head(enc_data_addr)
            if next_head_addr != idc.BADADDR: 
                read_size = next_head_addr - enc_data_addr
            else: #未获取到 则通过判断0
                zero_num = 0 #连续3个0就算末尾
                for data_index in range(1, 30001):
                    cur_byte = ida_bytes.get_byte(enc_data_addr + data_index)
                    zero_num = zero_num + 1 if cur_byte == 0 else 0
                    if zero_num >= 3:
                        break
                read_size = data_index

        return idc.get_bytes(enc_data_addr, read_size)
    
    emulator = DestringEmulate() #模拟执行器
    op_dict = get_emu_opcodes(de_info) 
    fuzzy_size = sum([len(op_dict[key]) for key in op_dict]) #大概的字节码size
    emulator.init_emu(de_info.insns[0], fuzzy_size) #初始化模拟器
    # 映射字节码到模拟执行器中
    for addr in op_dict:
        opcode = op_dict[addr]
        emulator.write_opcode(opcode, addr)

    enc_data_addr:int = de_info.extra_info['enc_data'] #加密字符串数据地址
    enc_data = get_enc_data(enc_data_addr) #加密后的字符串数据
    emulator.write_enc_data(enc_data_addr, enc_data)

    dec_data_addr:int = de_info.extra_info['dec_data']
    emulator.init_dec_data(dec_data_addr)

    #先执行一下两个lea 以防万一其不在连续的asm片段中
    lea1_start = de_info.insns[de_info.extra_info['lea_enc']]
    lea1_end = lea1_start + len(op_dict[lea1_start])

    lea2_start = de_info.insns[de_info.extra_info['lea_dec']]
    lea2_end = lea2_start + len(op_dict[lea2_start])
    emulator.start_dec_emu(lea1_start, lea1_end)
    emulator.start_dec_emu(lea2_start, lea2_end)

    # 开始模拟执行
    s_addr = de_info.insns[0] #开始执行地址
    e_addr = de_info.insns[-1] #结束执行地址 无论是sig1还是sig2都是执行到mov *, 1处
    if (not emulator.start_dec_emu(s_addr, e_addr)):
        return "emu_err" #模拟执行失败
    
    dec_str = "" #解密后的字符串
    try:
        dec_str = emulator.read_dec_string(de_info.extra_info['dec_str_len'])
    except Exception as e: #解码错误 模拟执行中有错误
        dec_str = "dec_err"
        logger.error("read_dec_string err: " + str(e))
    return dec_str

def patch_destring_asm(de_info:DeAsmInfo, patch_only_dec:bool = False) -> Tuple[int, int]:
    """Patch解密逻辑为NOP以及Patch解密处为原始字符串

    Args:
        de_info (DeAsmInfo): 解密片段信息
        patch_only_dec (bool): 只patch解密后的字符串
        
    Returns:
        tuple: (patch nop大小, pathc str大小)
    """
    #将所有涉及到的汇编片段Patch为NOP
    patch_nop_size = 0 #总共patch为nop的大小
    if not patch_only_dec:
        for addr in de_info.insns:
            insn_size = idc.get_item_size(addr)
            nop_bytes = b'\x90' * insn_size
            ida_bytes.patch_bytes(addr, nop_bytes)
            patch_nop_size += insn_size 

    #将解密字符串放置地址处Patch为字符串字节
    patch_str_size = 0
    dec_string_addr = de_info.extra_info['dec_data']
    string_bytes = de_info.dec_str.encode('utf-8') + b'\x00'
    ida_bytes.patch_bytes(dec_string_addr, string_bytes)
    patch_str_size = len(string_bytes)
    idc.create_strlit(dec_string_addr, dec_string_addr + patch_str_size) #将数据分析为string
    return (patch_nop_size, patch_str_size)

def dec_func():
    def handle_func(func_t:ida_funcs.func_t) -> bool:
        """处理一个函数的解密片段

        Args:
            func_t (ida_funcs.func_t): 函数

        Returns:
            bool: 是否处理成功
        """
        #ida_kernwin.show_wait_box("开始搜索解密汇编片段...")
        destring_infos:List[DeAsmInfo] = get_destring_info(func_t) #获取解密字符串汇编片段信息
        #if ida_kernwin.user_cancelled():
            #ida_kernwin.hide_wait_box()
            #return False#用户取消操作

        #ida_kernwin.replace_wait_box("开始模拟执行汇编片段...")
        task_num = len(destring_infos) #总共需要模拟执行的次数
        for i, one_info in enumerate(destring_infos):
            #ida_kernwin.replace_wait_box("模拟执行: {}/{}...".format(i + 1, task_num))
            asm_begin = one_info.insns[0] #片段开始地址
            destr = emu_destring_logic(one_info)
            if (destr == "emu_err"):
                logger.error("[{:02d}] [{:#x}] emu failed!".format(i, asm_begin))
                return False
            elif (destr == "dec_err"):
                logger.error("[{:02d}] [{:#x}] dec failed!".format(i, asm_begin))
                return False

            one_info.dec_str = destr #赋值
            logger.debug("[{:02d}] [{:#x}] dec str: {}".format(i, asm_begin, destr)) #解密后的字符串
            #if ida_kernwin.user_cancelled():
                #ida_kernwin.hide_wait_box()
                #return False
        
        #ida_kernwin.replace_wait_box("开始Patch汇编片段...")
        for i, one_info in enumerate(destring_infos):
            #ida_kernwin.replace_wait_box("Patch字节: {}/{}...".format(i + 1, task_num))
            pnop, pstr = patch_destring_asm(one_info, True) #patch nop容易出问题, 把正常指令也patch进行了
            logger.debug("[{:02d}] patch asm[{:#x}] -> nop[{}] | patch mem[{:#x}] -> str: [{}]".format(i, one_info.insns[0], pnop, one_info.extra_info['dec_data'], pstr))
            #if ida_kernwin.user_cancelled():
            #    break
        #ida_kernwin.hide_wait_box()
        return True

    #当前光标处的函数
    cur_ea = ida_kernwin.get_screen_ea()
    cur_func = ida_funcs.get_func(cur_ea) #获取当前函数
    if cur_func is None:
        logger.error("get func err")
        return
    handle_func(cur_func)

    '''
    ida_kernwin.show_wait_box("开始处理...")
    all_func_eas = list(idautils.Functions())
    task_num = len(all_func_eas) #总共需要处理的次数
    for i, ea in enumerate(all_func_eas):
        ida_kernwin.replace_wait_box("正在处理: {}/{}...".format(i + 1, task_num))
        cur_func = ida_funcs.get_func(ea)
        if cur_func is None:
            continue
        if not handle_func(cur_func): #处理失败
            break
        if ida_kernwin.user_cancelled():
            break
    ida_kernwin.hide_wait_box()
    '''

def handle_insns(eas:list, emu_flag:bool = True, patch_flag:bool = True, patch_only_flag:bool = True) -> bool:
    cur_de_info:DeAsmInfo = DeAsmInfo()
    find_sig_func = get_find_sig()
    next_index, find_flag = 0, False
    while True:
        find_ok, next_index = find_sig_func(eas, next_index, cur_de_info)
        if find_ok:
            find_flag = True
            break
        else:
            if next_index == -1:
                break
            elif next_index == -2:
                break
    if not find_flag:
        logger.warning("can't find sig!")
        return False
    logger.info("[{:#x}] {}".format(cur_de_info.insns[0], cur_de_info))

    if emu_flag:
        asm_begin = cur_de_info.insns[0] #片段开始地址
        destr = emu_destring_logic(cur_de_info)
        if (destr == "emu_err"):
            logger.error("[{:#x}] emu failed!".format(asm_begin))
            return False
        elif (destr == "dec_err"):
            logger.error("[{:#x}] dec failed!".format(asm_begin))
            return False
        cur_de_info.dec_str = destr #赋值
        logger.debug("[{:#x}] dec str: {}".format(asm_begin, destr)) #解密后的字符串
        
    if emu_flag and patch_flag: #模拟后才能patch
        pnop, pstr = patch_destring_asm(cur_de_info, patch_only_flag)
        logger.debug("patch asm[{:#x}] -> nop[{}] | patch mem[{:#x}] -> str: [{}]".format(cur_de_info.insns[0], pnop, cur_de_info.extra_info['dec_data'], pstr))
    return True

class SelectForm(ida_kernwin.Form):
    class SelectInsnsEmbeddedChooserClass(ida_kernwin.Choose):
        def __init__(self, title, new_items:List[int], flags = 0):
            ida_kernwin.Choose.__init__(self,
                            title,
                            [["Address", 10 | ida_kernwin.Choose.CHCOL_HEX], ["Insn", 30 | ida_kernwin.Choose.CHCOL_PLAIN]],
                            flags=flags,
                            embedded=True, width=40, height=5)
        
            self.items = []
            self.SetItems(new_items)
        
        def SetItems(self, new_items:List[int]):
            inter_items = []
            for ea in new_items:
                cur_item = [hex(ea), idc.GetDisasm(ea)]
                inter_items.append(cur_item)
            self.items = inter_items

        def GetItems(self) -> List[int]:
            return [int(item[0], 16) for item in self.items]

        def OnGetLine(self, n):
            return self.items[n]

        def OnGetSize(self):
            n = len(self.items)
            return n
        
        def OnSelectLine(self, sel):
            if len(sel) > 0:
                sel_item = self.items[sel[0]]
                sel_ea = int(sel_item[0], 16)
                idc.jumpto(sel_ea) #跳转

        def OnDeleteLine(self, sel):
            new_items = [self.items[i] for i in range(len(self.items)) if i not in sel]
            self.items = new_items
            return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(sel[0])
        
        def OnInsertLine(self, sel):
            new_sel = len(self.items) if len(sel) == 0 else sel[-1]
            cur_ea = idc.get_screen_ea()
            result = ida_kernwin.ask_addr(cur_ea, "Enter A Address:")
            if result:
                new_item = [hex(result), idc.GetDisasm(result)]
                self.items.insert(new_sel, new_item)
                return [ida_kernwin.Choose.ALL_CHANGED, new_sel]
            else:
                return [ida_kernwin.Choose.NOTHING_CHANGED, new_sel]
    
    def __init__(self, new_items:List[list]):
        self.ctrl_chooser = SelectForm.SelectInsnsEmbeddedChooserClass("EditInsns", new_items, flags=ida_kernwin.Choose.CH_MULTI)
        self.invert = False
        ida_kernwin.Form.__init__(self, r"""BUTTON YES NONE
BUTTON CANCEL NONE
Form SelectDecInsns

<##Action##Enable Emulate:{rCboxEmu}> <Enbale Patch:{rCboxPatch}> <Only Patch Dec:{rCboxPatchOnly}>{cGroupAction}> 
<Edit Insns:{cEChooser}>
<##OK:{iBtnOK}> <##CANCEL:{iBtnCANCEL}>  
""", {
        'cGroupAction': ida_kernwin.Form.ChkGroupControl(("rCboxEmu", "rCboxPatch", "rCboxPatchOnly")),
        'cEChooser' : ida_kernwin.Form.EmbeddedChooserControl(self.ctrl_chooser),
        'iBtnOK': ida_kernwin.Form.ButtonInput(self.OnBtnOK),
        'iBtnCANCEL': ida_kernwin.Form.ButtonInput(self.OnBtnCANCEL),
    })
    
    def OnBtnOK(self, code=0):
        select_insns = self.get_select_insns()
        emu_flag = self.GetControlValue(self.rCboxEmu)
        patch_flag = self.GetControlValue(self.rCboxPatch)
        patch_only_flag = select_form.GetControlValue(self.rCboxPatchOnly) #只patch放置解密字符串处
        handle_insns(select_insns, emu_flag, patch_flag, patch_only_flag)

    def OnBtnCANCEL(self, code=0):
        global select_form
        if select_form:
            select_form.Close(1)

    def get_select_insns(self):
        return self.ctrl_chooser.GetItems()
    
select_form:SelectForm = None
def dec_select():
    select_start = idc.read_selection_start()
    select_end = idc.read_selection_end()
    if (select_start == idc.BADADDR) or (select_end == idc.BADADDR):
        logger.warning("no select range!")
        return
    
    ea_lists = list(idautils.Heads(select_start, select_end))
    if len(ea_lists) == 0:
        logger.warning("no select insns!")
        return

    global select_form #释放之前编译的Form
    if select_form != None:
        select_form.Free()

    select_form = SelectForm(ea_lists)
    select_form.modal = False
    select_form.Compile() #编译
    select_form.rCboxEmu.checked = True
    select_form.rCboxPatch.checked = True
    select_form.rCboxPatchOnly.checked = True
    select_form.Open()

ACTION_NAME_0 = "wxd_dec_func"
ACTION_NAME_1 = "wxd_dec_select"
class decstring_t(ida_kernwin.action_handler_t):
    def __init__(self, action):
        ida_kernwin.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_NAME_0:
            dec_func()
        elif self.action == ACTION_NAME_1:
            dec_select()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def main():
    for action_name, popup_txt in [
        (ACTION_NAME_0, "dec func"),
        (ACTION_NAME_1, "dec select"),
    ]:
        desc = ida_kernwin.action_desc_t(
        action_name, popup_txt, decstring_t(action_name))
        if ida_kernwin.register_action(desc):
            print("[wxd] Registered action \"%s\"" % action_name)
    
    disam_form = ida_kernwin.find_widget("IDA View-A")
    if disam_form == None:
        logger.error("can't find disam form!")
        return
    ida_kernwin.attach_action_to_popup(disam_form, None, ACTION_NAME_0, "[WXD] DEC/")
    ida_kernwin.attach_action_to_popup(disam_form, None, ACTION_NAME_1, "[WXD] DEC/")

    

main()