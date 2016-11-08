#!/bin/bash

#建立检查结果文件
cd ~
filePath='Baseline'
resultFile=CheckResult-$(date -d today +%Y%m%d%H%M).txt
summaryFile=Summary-$(date -d today +%Y%m%d%H%M).txt
#判断存储结果文件的文件夹是否存在，不存在则新建
if [ ! -d $filePath ];then
    mkdir $filePath
fi
cd $filePath
touch $resultFile
touch $summaryFile
score=0
totalScore=0


#以下执行基本的系统检查
function check()
{
    echo "********************************************************************************" > ${resultFile}
    echo "主机基线检查结果: " >> ${resultFile}
    echo "********************************************************************************" >> ${resultFile}

    echo "================================================================================" >> ${resultFile}
    echo "一、服务安全" >> ${resultFile}

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SSH V2 检查" >> ${resultFile}
    # cat /etc/ssh/sshd_config | grep -E "Protocol" | grep -v "#" | awk -F' '  '{if($2==2){print "SSH V2 版本符合要求，5%";$score+=5;}else{print "SSH V2 版本不符要求，5%"}}' >> ${resultFile}
    tmp=`cat /etc/ssh/sshd_config | grep -E "Protocol" | grep -v "#"`
    arr=(${tmp//,/ })
    # echo ${arr[1]}
    if [[ ${arr[1]}==2 ]]; then
        echo "SSH V2 版本符合要求" >> ${resultFile}
        let score=score+5
    else
        echo "SSH V2 版本不符要求" >> ${resultFile}
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "禁止root用户登录检查" >> ${resultFile}
    #grep "^PremitRootLogin" /etc/ssh/sshd_config | grep no >> ${resultFile}
    tmp=`cat /etc/ssh/sshd_config | grep -E "^PermitRootLogin no"`
    if [ "$tmp" = "" ]; then
        echo "root用户登录不符要求" >> ${resultFile}
    else 
	   echo "root用户登录符合要求" >> ${resultFile}
        let score=score+4
    fi

    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "安全加密算法检查" >> ${resultFile}
    tmp=`grep "^Ciphers" /etc/ssh/sshd_config | grep ".*"`
    if [[ x"$tmp" = x ]]; then
        echo "安全加密算法不符要求" >> ${resultFile}
    else
        echo "安全加密算法符合要求" >> ${resultFile}
        let score=score+4
    fi
    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SNMP检查" >> ${resultFile}
    #判断SNMP服务是否开启
    tmp=`service snmpd status | grep inactive`
    if [[ x"$tmp" = x ]]; then #为空，表明snmp开启
        tmp=`cat /etc/snmp/snmpd.conf | grep "^com2sec" | grep -E 'public|private'`
        if [[ x"$tmp" = x ]]; then
            echo "SNMP配置符合要求" >> ${resultFile}
            let score=score+6
        else
            echo "SNMP配置不符要求" >> ${resultFile}
        fi
        #检查是否配置snmp v3用户
        tmp=`cat /etc/snmp/snmpd.conf | grep rouser`
        if [[ x"$tmp" = x ]]; then
            echo "未配置SNMP V3用户，不符" >> ${resultFile}
        else
            echo "已配置SNMP V3用户，符合" >> ${resultFile}
            let score=score+4
        fi
    else
        echo "SNMP服务未开启" >> ${resultFile}
    fi
    
    echo "============================================================" >> ${resultFile}
    echo "============================================================" >> ${resultFile}
    echo "二、账户管理" >> ${resultFile}
    
    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "当前用户列表" >> ${resultFile}
    cat /etc/passwd >> ${resultFile}
    #echo "用户帐号由客户业务决定,符合，3%" >> ${resultFile}
    #let score=score+3

    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "登录超时策略检查" >> ${resultFile}
    tmp=`cat /etc/profile | grep TMOUT`
    if [[ x"$tmp" = x ]]; then
        echo "未设置登录超时" >> ${resultFile}
    else
        num=${tmp:6}
        if [[ ${num} < "901" ]]; then
            echo "登录超时设置符合要求" >> ${resultFile}
            let score=score+4
        else
            echo "登录超时设置不符要求" >> ${resultFile}
	fi
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "口令检查" >> ${resultFile}
    emtPwd=`awk -F: '($2 == " ") { print $1 }' /etc/shadow`
    if [[ x"$emtPwd" = x ]]; then
        echo "不存在空口令账号" >> ${resultFile}
        let score=score+6
    else
        echo "存在空口令账号" >> ${resultFile}
    fi

    #密码天数检查
    tmp=`cat /etc/login.defs | grep -E "^PASS_MAX_DAYS"`
    if [[ ${tmp:15} < "91" ]]; then
        echo "新建用户的密码最长使用天数设置符合要求" >> ${resultFile}
        let score=score+4
    else
        echo "新建用户的密码最长使用天数设置不符要求" >> ${resultFile}
    fi
    tmp=`cat /etc/login.defs | grep -E "^PASS_WARN_AGE"`
    if [[ ${tmp:14:2} < "15" ]]; then
        echo "新建用户的密码到期提前提醒天数设置符合要求" >> ${resultFile}
        let score=score+4
    else
        echo "新建用户的密码到期提前提醒天数设置不符要求" >> ${resultFile}
    fi
    #let score=score+1

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "尝试和锁定策略检查" >> ${resultFile}
    tmp=`cat /etc/pam.d/sshd | grep pam_tally2.so`
    if [[ x"$tmp" = x ]]; then
        echo "未设置尝试和锁定策略" >> ${resultFile}
    else
        #denynum=${tmp#*deny=:0:1}
        denynum=${tmp#*deny=}
        if [[ ${denynum:0:1} < "7" ]]; then
            echo "密码锁定次数符合要求" >> ${resultFile}
            let score=score+4
        else
            echo "密码锁定次数不符要求" >> ${resultFile}
        fi
        utnum=${tmp#*unlock_time=}
        if [[ ${utnum:0:4} > "1799" ]]; then
            echo "锁定时间符合要求" >> ${resultFile}
            let score=score+4
        else
            echo "锁定时间不符要求" >> ${resultFile}
        fi
    fi

    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "系统口令策略检查" >> ${resultFile}
    tmp=`cat /etc/pam.d/system-auth | grep remember`
    if [[ x"$tmp" = x ]]; then
        echo "密码相同策略未设置" >> ${resultFile}
    else
        rnum=${tmp#*remember=}
        if [[ ${rnum:0:1} > "4" ]]; then
            echo "密码相同策略符合要求" >> ${resultFile}
            let score=score+6
        else
            echo "密码相同策略不符要求" >> ${resultFile}
        fi
    fi
    tmp=`cat /etc/pam.d/system-auth | grep pam_cracklib.so`
    if [[ x"$tmp" = x ]]; then
        echo "密码复杂性策略未设置" >> ${resultFile}
    else
        mlnum=${tmp#*minlen=}
        if [[ ${mlnum:0:1} > "7" ]]; then
            echo "密码最短长度符合要求" >> ${resultFile}
            let score=score+5
        else
            echo "密码最短长度不符要求" >> ${resultFile}
        fi
        dcnum=${tmp#*dcredit=}
        if [[ ${dcnum:0:2} = "-1" ]]; then
            echo "密码至少含一个数字符合要求" >> ${resultFile}
            let score=score+5
        else
            echo "密码至少含一个数字不符要求" >> ${resultFile}
        fi
        ucnum=${tmp#*ucredit=}
        if [[ ${ucnum:0:2} = "-1" ]]; then
            echo "密码至少含一个大写字母符合要求" >> ${resultFile}
            let score=score+5
        else
            echo "密码至少含一个大写字母不符要求" >> ${resultFile}
        fi
        lcnum=${tmp#*lcredit=}
        if [[ ${lcnum:0:2} = "-1" ]]; then
            echo "密码至少含一个小写字母符合要求" >> ${resultFile}
            let score=score+5
        else
            echo "密码至少含一个小写字母不符要求" >> ${resultFile}
        fi
        ocnum=${tmp#*ocredit=}
	#echo ${ocnum}
        if [[ ${ocnum:0:2} = "-1" ]]; then
            echo "密码至少含一个特殊字母符合要求" >> ${resultFile}
            let score=score+5
        else
            echo "密码至少含一个特殊字母不符要求" >> ${resultFile}
        fi
    fi

    echo "============================================================" >> ${resultFile}
    echo "============================================================" >> ${resultFile}
    echo "三、认证授权" >> ${resultFile}

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "使用PAM su到root状态检查" >> ${resultFile}
    tmp=`cat /etc/pam.d/su | grep -E "group=wheel"`
    if [[ x"$tmp" = x ]]; then
        echo "设置su权限不符要求" >> ${resultFile}
        
    else
        echo "设置su权限符合要求" >> ${resultFile}
        let score=score+4
    fi


    echo "------------------------------------------------------------" >> ${resultFile}
    echo "禁用系统账号" >> ${resultFile}
    echo "系统各账号状态如下：" >> ${resultFile}
    cat /etc/passwd >> ${resultFile}
     
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "umask值检查" >> ${resultFile}
    tmp=`cat /etc/profile | grep -E "umask 027"`
    #echo ${tmp}
    if [[ x"$tmp" = x ]]; then
        echo "UMASK值不符要求" >> ${resultFile}
    else
        echo "UMASK值符合要求" >> ${resultFile}
        let score=score+4
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "记录关键目录权限" >> ${resultFile}
    ls -la /etc/ >> ${resultFile}

    echo "============================================================" >> ${resultFile}
    echo "============================================================" >> ${resultFile}
    echo "四、日志审计" >> ${resultFile}

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "启用日志记录检查" >> ${resultFile}
    tmp=`cat /etc/rsyslog.conf | grep -E "^*.* @"`
    if [[ x"$tmp" = x ]]; then
        echo "日志服务器配置不符要求" >> ${resultFile}
    else
        echo "日志服务器符合要求" >> ${resultFile}
        let score=score+4
    fi
    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "记录系统安全事件检查" >> ${resultFile}
    tmp=`cat /etc/rsyslog.conf | grep -E "^*.err;kern.debug;daemon.notice;"`
    if [[ x"$tmp" = x ]]; then
        echo "日志记录配置不符要求" >> ${resultFile}
    else
        echo "日志记录配置符合要求" >> ${resultFile}
        let score=score+4
    fi

    echo "============================================================" >> ${resultFile}
    echo "============================================================" >> ${resultFile}
    echo "五、系统文件" >> ${resultFile}

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "隐藏系统提示信息检查" >> ${resultFile}
    cat /etc/issue >> ${resultFile}

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "NTP服务器设置检查" >> ${resultFile}
    tmp=`cat /etc/ntp.conf | grep "10.16.1.41"`
    if [[ x"${tmp}" = x ]]; then
        echo "NTP服务器不符要求" >> ${resultFile}
    else
        echo "NTP服务器符合要求" >> ${resultFile}
        let score=score+4
    fi

}

check
echo "总分为：$score" >> ${resultFile}
let score_No=100-${score}
echo "********************************************************************************" >> ${summaryFile}
echo "脚本检查符合项：(总分为：$score)" >> ${summaryFile}
echo "********************************************************************************" >> ${summaryFile}
cat ${resultFile} | grep "符合" >> ${summaryFile}
echo "********************************************************************************" >> ${summaryFile}
echo "脚本检查不符项：（总分为：${score_No}）" >> ${summaryFile}
echo "********************************************************************************" >> ${summaryFile}
cat ${resultFile} | grep "不符" >> ${summaryFile}
