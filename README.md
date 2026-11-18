# Ledger App SSH Agent
Using the **SSH / PGP Agent** app `v0.0.12`, we can consistently derive the same ***SSH*** key from the *seed* saved within the *Ledger.*
> Note: The private ***SSH*** key never leaves the *Ledger* device.


*Forked* from: [https://github.com/LedgerHQ/app-ssh-agent](https://github.com/LedgerHQ/app-ssh-agent).

* I updated the *codebase* from ***Python 2*** to ***Python 3***, and created an updated ***`README.md`*** to follow along.


> It is *recommended* to use this as a **backup / recovery** key for accessing *servers* for *example,* and to primarily use the [Ledger App Security Key](https://github.com/LedgerHQ/app-security-key/blob/main/doc/usecase-git-auth.md) as the ***SSH*** login credential if using a *Ledger.*


If using Windows:
-----------------------------------------

> We must use **Linux / WSL**.

To activate **WSL 2** on *Windows* if it isn't already configured, open ***PowerShell*** as an *administrator* and run the command and follow the installation:

```powershell
wsl --install
```


> First, we must have the *Ledger* be readable and accessible via **WSL** from *Windows.*

*Download:* 
> [https://github.com/dorssel/usbipd-win/releases](https://github.com/dorssel/usbipd-win/releases)

Run and install based upon which ***CPU*** the system has:
> * ***usbipd-win_5.3.0_arm64.msi***
> * ***usbipd-win_5.3.0_x64.msi***

Open ***PowerShell*** and run the command:

```powershell
usbipd list
```

#### Sample output:

```powershell
BUSID  VID:PID        DEVICE                                                        STATE
1-1    <XXXX>:<AAAA>  USB Input Device                                              Not shared
1-3    <YYYY>:<BBBB>  USB Input Device, Nano X                                      Not shared
1-4    <ZZZZ>:<CCCC>  USB Input Device                                              Not shared
```

> We must activate **`STATE`** on the *Ledger* device from ***`'Not shared'`*** to ***`'Shared'`**.*

Grab the **`<BUSID>`**. In this *example,* it is ***`'1-3'`**:*

```powershell
usbipd bind --busid 1-3
usbipd attach --wsl --busid 1-3
```

#### Sample output:

```powershell
usbipd: info: Using WSL distribution 'Ubuntu' to attach; the device will be available in all WSL 2 distributions.
usbipd: info: Detected networking mode 'nat'.
usbipd: info: Using IP address XXX.XX.XX.X to reach the host.
```

Now, run *` usbipd list `* again to confirm the **`STATE`** of the *Ledger* device is ***`'Shared'`**:*

```powershell
usbipd list
```

#### Sample output:

```powershell
BUSID  VID:PID        DEVICE                                                        STATE
1-1    <XXXX>:<AAAA>  USB Input Device                                              Not shared
1-3    <YYYY>:<BBBB>  USB Input Device, Nano X                                      Shared
1-4    <ZZZZ>:<CCCC>  USB Input Device                                              Not shared
```





Linux / WSL (Debian based):
-----------------------------------------

Install *dependencies:*

```bash
sudo apt-get install python3
sudo apt-get install libusb-1.0-0-dev
sudo apt install usbutils
```

Create and activate a ***virtual environment**.*
In this *example,* we will create it in the *home directory:*

```bash
python3 -m venv ledger_agent
source ledger_agent/bin/activate
```

Now, install ***Python 3*** *dependencies:*

```bash
pip3 install ledger_agent
```

*Clone* the project over and go into the *directory.*
In this *example,* we will *clone* it into the *home directory:*

```bash
git clone https://github.com/ricky-i2p/ledger-app-ssh-agent.git
cd app-ssh-agent/
```

Now we will *generate* our ***public key*** from the *Ledger* and `print` it out on the *terminal:*

```bash
sudo /home/<USER>/ledger_agent/bin/python3 getPublicKey.py
```


#### Sample output:

```bash  
HID => <IDENTIFIER_1>
```

Now it will ask for confirmation on the *Ledger*, confirm ***'Provide public key?'***.
#### Sample output:

```bash
HID <= <IDENTIFIER_2>
ecdsa-sha2-nistp256 <KEY_BASE64>
```

> Now we must hop over to the **VPS** to continue.



## VPS (Linux based):

Login and save the outputted text ***`'ecdsa-sha2-nistp256 <KEY_BASE64>'`*** from *earlier* into the *`.ssh`* key list:

```bash
nano ~/.ssh/authorized_keys
```

If we see this *error:*


> `[ Error writing /home/<USER>/.ssh/authorized_keys: No such file or directory ]`

Create the *`.ssh`* *directory* first:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

Now save the ***`'ecdsa-sha2-nistp256 <KEY_BASE64>'`*** into the *`.ssh`* key list:

```bash
nano ~/.ssh/authorized_keys
```

And now grant the *required* privileges:

```bash
chmod 600 ~/.ssh/authorized_keys
```




## Linux/WSL (Debian based):

Now it is time to run the program that will allow our *Ledger* to sign and confirm the ***SSH*** connection.
In the same *terminal,* enter:

```bash
sudo /home/<USER>/ledger_agent/bin/python3 agent.py --key <KEY_BASE64>
```

#### Sample output:

```bash
Export these variables in your shell:
export SSH_AUTH_SOCK=/tmp/<NAME>/agent.sock
export SSH_AGENT_PID=<XXXXX>
Agent running ...
```

Keep that *terminal* process running and open up a separate, new **Linux / WSL** *terminal* window and *export* the given ***`SSH_AUTH_SOCK`*** and ***`SSH_AGENT_PID`**:*

```bash
export SSH_AUTH_SOCK=/tmp/<NAME>/agent.sock 
export SSH_AGENT_PID=<XXXXX>
```

The *socket directory* and *socket* are ***root-owned***, so for this *example* we will temporarily give ourselves permission to *execute* these paths:

```bash
sudo chown <USER>:<USER> /tmp/<NAME> /tmp/<NAME>/agent.sock
ssh-add -L
```

Verify the output matches the ***`<KEY_BASE64>`***, and now it will have ` ' Ledger SSH key'` attached at the end:

```bash
ecdsa-sha2-nistp256 <KEY_BASE64> Ledger SSH key
```

Now with the **SSH / PGP Agent** app open on the *Ledger*, ***SSH*** into the **VPS** with the `-v` *flag:*

```bash
ssh -v <USER>@<HOSTNAME>
```

On the *Ledger*, confirm ***'Connect SSH user &lt;USER&gt;'**.*




------------------------------------------------------------------------------------------------------
**Ta-da**, *success!* We can now ***'Ctrl + C'*** or close out of the terminal running ***agent.py**.*

When done, if using *Windows* we must detach the *Ledger* from **WSL** so we can use it normally again on *Windows.*
While attached, *Windows* can’t use the *Ledger*, so detach it from ***PowerShell*** when done.



## Windows:

In ***PowerShell***, run the command:

```powershell
usbipd detach --busid <BUSID>
```





## Donate:

If this was helpful or useful, consider supporting.

```text
XMR: 83o2qaBv2WGW62aQKSxFMSHndSCAdjfD1Ag2WhenZt1YTZjVmYafrmbMAKtvyQUFfqWCvJhag2WaELZkprdRt5VkFBxNuk3
```
