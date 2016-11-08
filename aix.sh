#!/bin/bash

#建立检查结果文件
cd ~
filePath='Baseline/Check'
resultFile=CheckResult-$(date +%Y-%m-%d-%H:%-M:%-S).txt
summaryFile=Summary-$(date +%Y-%m-%d-%H:%-M:%-S).txt
mkdir -p $filePath
cd $filePath
touch $resultFile
touch $summaryFile
score=0
totalScore=0

function_check
{ 
#系统服务检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "已开启系统服务检查" >> ${resultFile}
    echo "------------------------------------------------------------" >> ${resultFile}
    ACTIVE_SERVICES=$(lssrc -a | grep active | awk '{print $1}')
    for i in $ACTIVE_SERVICES;do
        echo $i is active >> ${resultFile}
    done

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "未开启系统服务检查" >> ${resultFile}
    echo "------------------------------------------------------------" >> ${resultFile}
    INOPERACTIVE_SERVICES=$(lssrc -a | grep inoperative | awk '{print $1}')
    for i in $INOPERACTIVE_SERVICES;do
        echo $i is inoperative >> ${resultFile}
    done

#SSH基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SSH_V2检查" >> ${resultFile}
    SSH_V2=$(cat /etc/ssh/sshd_config | grep -E "Protocol 2" | grep -v "#")
    if [ "$SSH_V2" = "" ];then
        echo "未启用SSH_V2协议(未配置)" >> ${resultFile}
    else
        echo "已启用SSH_V2协议(符合)" >> ${resultFile}
        let score=score+5
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "限制ROOT用户登录" >> ${resultFile}
    SSH_V2=$(cat /etc/ssh/sshd_config | grep -E "PermitRootLogin no" | grep -v "#")
    if [ "$SSH_V2" = "" ];then
        echo "未限制ROOT用户登录(未配置)" >> ${resultFile}
    else
        echo "已限制ROOT用户登录(符合)" >> ${resultFile}
        let score=score+5
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "是否配置安全加密算法" >> ${resultFile}
    CIPHERS=$(grep "^Ciphers" /etc/ssh/sshd_config| grep ".*")
    if [ "$CIPHERS" = "" ];then
        echo "未配置安全加密算法(未配置)" >> ${resultFile}
    else
        echo "已配置安全加密算法(符合)" >> ${resultFile}
        let score=score+5
    fi

#SNMP基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SNMP服务状态检查" >> ${resultFile}
    SNMP_STATUS=$(lssrc -s snmpd | grep -E "active" | awk '{print $4}')
    if [ "$SNMP_STATUS" = "active" ];then
        echo "SNMP服务已启用(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "SNMP服务未启用(未配置)" >> ${resultFile}
    fi
    
#SNMP V3版本检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SNMP版本状态检查" >> ${resultFile}
    SNMP_VERSION=$(ls -l /usr/sbin/snmpd* | grep snmpdv3ne | wc -l)
    if [ $SNMP_VERSION == 2 ];then
        echo "使用SNMP_V3版本(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "使用SNMP_V1版本(未配置)" >> ${resultFile}
    fi

#SNMP默认团体名检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SNMP默认团体名Public检查" >> ${resultFile}
    COMMUNITY_PUBLIC=$(cat /etc/snmpdv3.conf | grep noAuthNoPriv | grep COMMUNITY | awk '{print $2}')
    if [ $COMMUNITY_PUBLIC == public ];then
        echo "默认团体名为public(未配置)" >> ${resultFile}
    else
        echo "默认团体名不为public" >> ${resultFile}
        let score=score+5
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SNMP默认团体名Private检查" >> ${resultFile}
    COMMUNITY_PRIVATE=$(cat /etc/snmpdv3.conf | grep noAuthNoPriv | grep COMMUNITY | awk '{print $2}')
    if [ "$COMMUNITY_PRIVATE" = "private" ];then
        echo "默认团体名为private(未配置)" >> ${resultFile}
    else
        echo "默认团体名不为private" >> ${resultFile}
        let score=score+5
    fi
    
#账户管理基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "登录超时策略检查" >> ${resultFile}
    TMOUT=$(cat /etc/profile | grep -E TMOUT | grep -v "#")
    if [ $TMOUT -eq 0 ];then
        echo "未配置登录超时策略(未配置)" >> ${resultFile}
    else
        echo "已配置登录超时策略(符合)" >> ${resultFile}
        let score=score+5
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "系统口令策略检查" >> ${resultFile}
    MAXAGE=$(lssec -f /etc/security/user -s default -a maxage | cut -f2 -d"=")
    if [ $MAXAGE -le 12 ]&&[ $MAXAGE -ne 0 ];then
        echo "口令生存周期小于等于90天(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "口令生存周期大于等于90天(未配置)" >> ${resultFile}
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "口令锁定策略" >> ${resultFile}
    PASSLOCK=$(lssec -f /etc/security/user -s default -a loginretries | cut -f2 -d"=")
    if [ $PASSLOCK -le 5 ]&&[ $PASSLOCK -ne 0 ];then
        echo "密码尝试次数小于等于5次(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "密码尝试次数大于等于5次(未配置)" >> ${resultFile}
    fi

#口令策略检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "密码长度检查" >> ${resultFile}
    MINLEN=$(lssec -f /etc/security/user -s default -a minlen | cut -f2 -d"=")
    if [ $MINLEN -ge 8 ]&&[ $MINLEN -ne 0 ];then
        echo "密码长度大于等于8位(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "密码长度小于等于8位(未配置)" >> ${resultFile}
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "字母检查" >> ${resultFile}
    MINALPHA=$(lssec -f /etc/security/user -s default -a minalpha | cut -f2 -d"=")
    if [ $MINALPHA -ge 2 ]&&[ $MINALPHA -ne 0 ];then
        echo "密码包含字母数大于等于2位(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "密码包含字母数小于等于2位(未配置)" >> ${resultFile}
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "特殊字符检查" >> ${resultFile}
    MINOTHER=$(lssec -f /etc/security/user -s default -a minother | cut -f2 -d"=")
    if [ $MINOTHER -ge 1 ]&&[ $MINOTHER -ne 0 ];then
        echo "密码包含1个以上特殊字符(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "未配置该项(未配置)" >> ${resultFile}
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "口令历史使用次数" >> ${resultFile}
    HISTSIZE=$(lssec -f /etc/security/user -s default -a histsize | cut -f2 -d"=")
    if [ $HISTSIZE -le 5 ]&&[ $HISTSIZE -ne 0 ];then
        echo "不能使用与前5次密码相同的密码(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "未配置口令历史使用次数(未配置)" >> ${resultFile}
    fi

#认证授权基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "UMASK检查" >> ${resultFile}
    UMASK=$(more /etc/security/user | grep -E "umask = 027")
    if [[ x"$UMASK" = x ]]; then
        echo "umask未配置为027(未配置)" >> ${resultFile}
    else
        echo "umask已配置为027(符合)" >> ${resultFile}
        let score=score+5
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "文件权限查看" >> ${resultFile}
    ls -l /etc/passwd >> ${resultFile}
    ls -l /etc/group >> ${resultFile}
    ls -l /etc/hosts >> ${resultFile}
    ls -l /etc/inittab >> ${resultFile}

#SysLog基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "SysLog服务状态检查" >> ${resultFile}
    SYSLOG_STATUS=$(lssrc -s syslogd | grep -E "active" | awk '{print $4}')
    if [ "$SYSLOG_STATUS" = "active" ];then
        echo "SYSLOG服务已启用(符合)" >> ${resultFile}
        let score=score+5
    else
        echo "SYSLOG服务未启用(未配置)" >> ${resultFile}
    fi
    
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "ERROR日志查询" >> ${resultFile}
    ERR=$(cat /etc/syslog.conf | grep -E err | grep -v "#")
    if [[ x"$ERR" = x ]];then
        echo "未记录ERROR日志(未配置)" >> ${resultFile}
    else
        echo "已记录ERROR日志(符合)" >> ${resultFile}
        let score=score+2
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "Alert日志查询" >> ${resultFile}
    ALERT=$(cat /etc/syslog.conf | grep -E alert | grep -v "#")
    if [[ x"$ALERT" = x ]];then
        echo "未记录Alert日志(未配置)" >> ${resultFile}
    else
        echo "已记录Alert日志(符合)" >> ${resultFile}
        let score=score+2
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "Crit日志查询" >> ${resultFile}
    CRIT=$(cat /etc/syslog.conf | grep -E cri | grep -v "#")
    if [[ x"$CRIT" = x ]];then
        echo "未记录CRIT日志(未配置)" >> ${resultFile}
    else
        echo "已记录CRIT日志(符合)" >> ${resultFile}
        let score=score+3
    fi

    echo "------------------------------------------------------------" >> ${resultFile}
    echo "Auth日志查询" >> ${resultFile}
    AUTH=$(cat /etc/syslog.conf | grep -E auth | grep -v "#")
    if [[ x"$AUTH" = x ]];then
        echo "未记录AUTH日志(未配置)" >> ${resultFile}
    else
        echo "已记录AUTH日志(符合)" >> ${resultFile}
        let score=score+3
    fi

#Banner基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "Banner信息检查" >> ${resultFile}
    Banner=$(more /etc/security/login.cfg | grep -E herald | grep -v "*")
    if [[ x"$Banner" = x ]]; then
        echo "未添加Banner信息(未配置)" >> ${resultFile}   
    else
        echo "已添加Banner信息(符合)" >> ${resultFile}
        let score=score+5
    fi
    
#NTP基线检查
    echo "------------------------------------------------------------" >> ${resultFile}
    echo "NTP服务器配置检查" >> ${resultFile}
    NTP_SERVER=$(cat /etc/ntp.conf | grep "server 10.16.1.41")
    if [[ x"${NTP_SERVER}" = x ]]; then
        echo "未配置NTP服务器(未配置)" >> ${resultFile}
    else
        echo "已配置NTP服务器(符合)" >> ${resultFile}
        let score=score+5
    fi
    echo "------------------------------------------------------------" >> ${resultFile}
}
function_check
echo "总分为：$score" >> ${resultFile}
let score_No=100-${score}
echo "********************************************************************************" >> ${summaryFile}
echo "脚本检查符合项：(总分为：$score)" >> ${summaryFile}
echo "********************************************************************************" >> ${summaryFile}
cat ${resultFile} | grep "符合" >> ${summaryFile}
echo "********************************************************************************" >> ${summaryFile}
echo "脚本检查未配置项：（总分为：${score_No}）" >> ${summaryFile}
echo "********************************************************************************" >> ${summaryFile}
cat ${resultFile} | grep "未配置" >> ${summaryFile}


