#pragma once
#include <string>

enum GETINFOTYPE {
	Constructor = 0,//制造商
	Trademarks,//商标
	SerialNumber,//序列号
	FirmwareRev,//固件版本
	ModelNumber//内部型号
};


union CpuFeaturesInfo1 {
	unsigned int all;
	struct {
		unsigned int sse3 : 1;       //！ <[0]simd流技术扩展3(SSE3) 
		unsigned int pclmulqdq : 1;  //！ <[1]PCLMULQDQ 
		unsigned int dtes64 : 1;     //！ <[2]64位DS区域
		unsigned int monitor : 1;    //！ <[3]显示器/等
		unsigned int ds_cpl : 1;     //！ <[4]CPL合格的调试存储 
		unsigned int vmx : 1;        //！ <[5]虚拟机技术 
		unsigned int smx : 1;        //！ <[6]安全模式扩展
		unsigned int est : 1;        //！ <[7]增强型英特尔Speedstep技术 
		unsigned int tm2 : 1;        //！ <[8]散热监控2 
		unsigned int ssse3 : 1;      //！ <[9]附加simd流技术扩展3
		unsigned int cid : 1;        //！ <[10]L1上下文ID 
		unsigned int sdbg : 1;       //！ <[11]IA32_DEBUG_INTERFACE MSR 
		unsigned int fma : 1;        //！ <[12]使用YMM状态FMA扩展
		unsigned int cx16 : 1;       //！ <[13]CMPXCHG16B 
		unsigned int xtpr : 1;       //！ <[14]xTPR更新控制
		unsigned int pdcm : 1;       //！ <[15]性能/调试能力MSR 
		unsigned int reserved : 1;   //！ <[16]保留 
		unsigned int pcid : 1;       //！ <[17]程序的上下文标识符 
		unsigned int dca : 1;        //！ <[18]回迁从内存映射设备
		unsigned int sse4_1 : 1;     //！ <[19]SSE4.1 
		unsigned int sse4_2 : 1;     //！ <[20]SSE4.2 
		unsigned int x2_apic : 1;    //！ <[21]x2APIC功能 
		unsigned int movbe : 1;      //！ <[22]MOVBE指令 
		unsigned int popcnt : 1;     //！ <[23]POPCNT指令
		unsigned int reserved3 : 1;  //！ <[24]使用TSC期限一次性操作 
		unsigned int aes : 1;        //！ <[25]AESNI指令 
		unsigned int xsave : 1;      //！ <[26]XSAVE/XRSTOR功能 
		unsigned int osxsave : 1;    //！ <[27]使XSETBV/XGETBV说明 
		unsigned int avx : 1;        //！ <[28]AVX指令扩展 
		unsigned int f16c : 1;       //！ <[29]16位浮点转换 
		unsigned int rdrand : 1;     //！ <[30]RDRAND指令 
		unsigned int not_used : 1;   //！ <[31]0(a.k.一。 HypervisorPresent)
	} fields;
};
static_assert(sizeof(CpuFeaturesInfo1) == 4, "Size check");

union CpuFeaturesInfo2 {
	unsigned int all;
	struct {
		unsigned int fpu : 1;        //！ <[0]浮点单元的片上 
		unsigned int vme : 1;        //！ <[1]虚拟8086模式增强 
		unsigned int de : 1;         //！ <[2]调试扩展程序
		unsigned int pse : 1;        //！ <[3]页大小扩展 
		unsigned int tsc : 1;        //！ <[4]时间戳计数器 
		unsigned int msr : 1;        //！ <[5]RDMSR和WRMSR说明
		unsigned int mce : 1;        //！ <[7]机器检查异常 
		unsigned int cx8 : 1;        //！ <[8]散热监控2 
		unsigned int apic : 1;       //！ <[9]APIC片上 
		unsigned int reserved1 : 1;  //！ <[10]保留
		unsigned int sep : 1;        //！ <[11]SYSENTER和SYSEXIT说明 
		unsigned int mtrr : 1;       //！ <[12]内存范围寄存器 
		unsigned int pge : 1;        //！ <[13]页全球位
		unsigned int mca : 1;        //！ <[14]机器检查架构 
		unsigned int cmov : 1;       //！ <[15]有条件的移动指令 
		unsigned int pat : 1;        //！ <[16]页属性表
		unsigned int pse36 : 1;      //！ <[17]36位页面大小扩展 
		unsigned int psn : 1;        //！ <[18]处理器序列号 
		unsigned int clfsh : 1;      //！ <[19]CLFLUSH指令
		unsigned int reserved2 : 1;  //！ <[20]保留 
		unsigned int ds : 1;         //！ <[21]的调试存储 
		unsigned int acpi : 1;       //！ <[22]TM和软件控制时钟 
		unsigned int mmx : 1;        //！ <[23]英特尔MMX技术
		unsigned int fxsr : 1;       //！ <[24]FXSAVE和FXRSTOR说明 
		unsigned int sse : 1;        //！ <[25]SSE 
		unsigned int sse2 : 1;       //！ <[26]SSE2 
		unsigned int ss : 1;         //！ <[27]自探听 
		unsigned int htt : 1;        //！ <[28]保留的最大APIC id字段有效 
		unsigned int tm : 1;         //！ <[29]散热监控 
		unsigned int reserved3 : 1;  //！ <[30]保留 
		unsigned int pbe : 1;        //！ <[31]挂起的分行符启用
	} fields;
};
static_assert(sizeof(CpuFeaturesInfo2) == 4, "Size check");

class IMGetData
{
public:
	IMGetData();
	~IMGetData();

	std::string GetCpuInfo(GETINFOTYPE GetDataType);
	CpuFeaturesInfo1 IMGetData::GetCpuFeaturesInfo1();
	CpuFeaturesInfo2 IMGetData::GetCpuFeaturesInfo2();
	std::string GetDiskInfo(GETINFOTYPE GetDataType);

};

