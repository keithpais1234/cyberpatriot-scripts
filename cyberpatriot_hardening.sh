#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "Are the forensics questions solved? (y/n)"
read forensics_response
echo "---------"

echo "Are Firefox settings correctly set? (y/n)"
read firefox_response
echo "---------"

echo "Please fill out information in the allowed directory. (Press Enter to continue)"
read
echo "---------"

echo "Check /etc/sudoers (Press Enter to continue)"
read
echo "---------"

# Backup and restore functions
backup_file() {
  local filepath="$1"
  local backup_dir="backup"
  mkdir -p $backup_dir
  cp -n "$filepath" "$backup_dir/"
  echo "Backup of $filepath created at $backup_dir/"
}

# Function to print differences
print_difference() {
  local current="$1"
  local allowed="$2"
  echo "Current vs allowed difference: $(comm -3 <(echo "$current" | sort) <(echo "$allowed" | sort))"
}

# Read allowed and default files
allowed_users=$(<allowed/allowed_users.txt)
allowed_admins=$(<allowed/allowed_admins.txt)
allowed_packages=$(grep -v '^#' allowed/allowed_packages.txt)

default_users=$(<defaults/default_users.txt)
default_groups=$(<defaults/default_groups.txt)
default_packages=$(<defaults/default_packages.txt)

# Combine allowed and default sets
total_users=$(echo "$default_users"$'\n'"$allowed_users" | sort | uniq)
total_groups=$(echo "$default_groups"$'\n'"$allowed_users" | sort | uniq)

# Check users
current_users=$(getent passwd | cut -d: -f1)
print_difference "$current_users" "$total_users"
echo "---------"

# Check groups
current_groups=$(getent group | cut -d: -f1)
print_difference "$current_groups" "$total_groups"
echo "---------"

# Check sudoers group
current_sudoers=$(getent group sudo | cut -d: -f4 | tr ',' '\n')
print_difference "$current_sudoers" "$allowed_admins"
echo "---------"

# Add new admin user
echo "Adding user 'parktudor'..."
useradd -m -s /bin/bash parktudor
echo "parktudor:GreatYear2019!@" | chpasswd
usermod -aG sudo parktudor
echo "User 'parktudor' added to sudo group."
echo "---------"

# UID 0 check
echo "Find UID/GID=0 users? (y/n)"
read uid_check
if [ "$uid_check" == "y" ]; then
  uid0_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
  if [ -n "$uid0_users" ]; then
    echo "WARNING: UID/GID=0 USERS FOUND"
    echo "$uid0_users"
    read -p "Press Enter to continue"
  else
    echo "No UID/GID=0 users found"
  fi
fi
echo "---------"

# Reset /etc/rc.local
echo "Reset /etc/rc.local? (y/n)"
read rc_local_response
if [ "$rc_local_response" == "y" ]; then
  backup_file /etc/rc.local
  cp defaults/default_rc.local /etc/rc.local
  echo "/etc/rc.local reset to default."
fi
echo "---------"

# Reset sources.list
echo "Reset sources.list? (y/n)"
read sources_response
if [ "$sources_response" == "y" ]; then
  codename=$(lsb_release -c -s)
  backup_file /etc/apt/sources.list
  echo "deb http://archive.ubuntu.com/ubuntu $codename main multiverse universe restricted" > /etc/apt/sources.list
  echo "deb http://archive.ubuntu.com/ubuntu $codename-security main multiverse universe restricted" >> /etc/apt/sources.list
  apt update
  echo "sources.list reset and updated."
fi
echo "---------"

# Enable automatic updates
echo "Please enable automatic updates. (Press Enter to continue)"
read
echo "---------"

# Change all users' passwords (not admins)
non_admin_users=$(comm -23 <(echo "$allowed_users" | sort) <(echo "$allowed_admins" | sort))
echo "Change all allowed users passwords? (y/n)"
read change_pw_response
if [ "$change_pw_response" == "y" ]; then
  for user in $non_admin_users; do
    echo "$user:Cyberpatriot1!" | chpasswd
    echo "Password for user $user changed."
  done
fi
echo "---------"

# Install OpenSSH if allowed
if grep -q 'openssh-server' <<< "$allowed_packages"; then
  echo "Installing and configuring OpenSSH..."
  apt install openssh-server -y
  echo "OpenSSH installed."
  
  echo "Reset /etc/ssh/sshd_config? (y/n)"
  read sshd_config_response
  if [ "$sshd_config_response" == "y" ]; then
    backup_file /etc/ssh/sshd_config
    cp defaults/default_sshd_config /etc/ssh/sshd_config
    systemctl restart ssh
    echo "/etc/ssh/sshd_config reset and SSH restarted."
  fi
fi
echo "---------"

# Secure sysctl
echo "Secure sysctl? (y/n)"
read sysctl_response
if [ "$sysctl_response" == "y" ]; then
  backup_file /etc/sysctl.conf
  cp defaults/default_sysctl.conf /etc/sysctl.conf
  sysctl -p
  echo "Sysctl secured."
fi
echo "---------"

# Enable firewall
echo "Enable firewall? (y/n)"
read firewall_response
if [ "$firewall_response" == "y" ]; then
  ufw enable
  ufw deny 23 2049 515 111
  echo "Firewall enabled with specific ports denied."
fi
echo "---------"

# Disable guest login
echo "Disable guest/automatic login? (y/n)"
read guest_login_response
if [ "$guest_login_response" == "y" ]; then
  echo -e "[SeatDefaults]\nallow-guest=false" > /etc/lightdm/lightdm.conf
  echo "Guest login disabled."
fi
echo "---------"

# Change root password
echo "Change root password? (y/n)"
read root_pw_response
if [ "$root_pw_response" == "y" ]; then
  echo "root:Cyberpatriot1!" | chpasswd
  echo "Root password changed."
fi
echo "---------"

# Disable root login
echo "Disable root login? (y/n)"
read disable_root_response
if [ "$disable_root_response" == "y" ]; then
  passwd -dl root
  echo "Root login disabled."
fi
echo "---------"

# Password policy enforcement
echo "Enable password policy? (y/n)"
read pw_policy_response
if [ "$pw_policy_response" == "y" ]; then
  apt install libpam-cracklib -y
  backup_file /etc/pam.d/common-password
  sed -i '/pam_unix.so/s/$/ minlen=8 remember=5/' /etc/pam.d/common-password
  echo "password requisite pam_cracklib.so retry=3 minlen=14 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
  echo "Password policy updated in /etc/pam.d/common-password."

  backup_file /etc/login.defs
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   30/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
  echo "Password policy updated in /etc/login.defs."
fi
echo "---------"

# Media file management
echo "View and delete .mp3 files? (y/n)"
read media_response
if [ "$media_response" == "y" ]; then
  media_files=$(find / -type f -iname "*.mp3" 2>/dev/null)
  echo "$media_files"
  echo "Total .mp3 files found: $(echo "$media_files" | wc -l)"
  echo "Delete all .mp3 files? (y/n)"
  read delete_media_response
  if [ "$delete_media_response" == "y" ]; then
    find / -type f -iname "*.mp3" -exec rm -f {} \;
    echo "All .mp3 files deleted."
  fi
fi
echo "---------"

# Change crucial file permissions
declare -A file_perms=(["/etc/passwd"]="644 root:root" ["/etc/shadow"]="640 root:shadow")
echo "Change crucial file permissions and ownership? (y/n)"
read perms_response
if [ "$perms_response" == "y" ]; then
  for file in "${!file_perms[@]}"; do
    perm=${file_perms[$file]}
    chmod "${perm%% *}" "$file"
    chown "${perm#* }" "$file"
   
