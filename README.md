# Malicious-Address-Confirm
 This is a combination of redacting your personal IP address/s and also check remaining address with AbuseIPDB for malicious addresses within your logs to aid in next steps in securing your SOHO or organization.
The images will show how to setup secure your API key in AWS Secrets Manager. 
<br />
<br />
<p align="center"> 1. When you log into your AWS console, and in the search bar type secrets manager and on the page, select "Store a new secret" 
 <br /> 
 <br />
<img src="https://i.imgur.com/OEj0VcS.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 2. On the next page under "Secret type" select "other type of secret" where under that you see an option for "API key" 
 <br />
 <br />
<img src="https://i.imgur.com/h0ses2s.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 3. For key/value pair input whatever you want to name your key and for the value input your api key. Proceed by selecting next 
 <br />
 <br />
<img src="https://i.imgur.com/OEj0VcS.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 4. Give your secret a name under "Secret name". If you would like to give a description, you can, it is optional. Proceed by selecting next 
 <br />
 <br />
<img src="https://i.imgur.com/wbnTHDm.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 5. This page is optional for rotating the secret, for the sake of testing, you can proceed and not modify anything 
 <br />
 <br />
<img src="https://i.imgur.com/V4Hcb1Z.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 6. The last page is to review to make sure everything is what you preferred in your configuration. 
 At the bottom you will see "Sample code", depending on what code you chose will dictate what code to copy and input into your own code. In my case I used Python3. After everyting is reviewed, select "Store" 
 <br />
 <br />
<img src="https://i.imgur.com/xqlplbd.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 7. After you select "store" you will get a green banner showing success 
 <br />
 <br />
<img src="https://i.imgur.com/O4qXGpp.png" height="80%" width="80%" alt="Store New Secret"/> </p>
<p align="center"> 8. After I updated my AWS access keys, I needed to update the keys also on my computer using the AWS CLI. I will assume that you already have the AWS CLI installed on your computer. If not, a quick google search or chatGPT will help you out.
      
       Configure AWS Credentials

You need to provide AWS credentials either via environment variables or using an AWS credentials file.
Option 1: Using AWS CLI to Configure Credentials

If you haven’t set up AWS credentials before, you can configure them using the AWS CLI:

In the CLI type what is within the quotes:

"aws configure"

This command will prompt you for:

    AWS Access Key ID: Found in the AWS Management Console under your IAM user or role.
    AWS Secret Access Key: Also found under your IAM user/role.
    Default region name: E.g., us-east-1.
    Default output format: Usually json.

The credentials will be saved in the ~/.aws/credentials file (Linux/Mac) or C:\Users\YOUR_USERNAME\.aws\credentials (Windows).

At this point you should be good to go. If you get any errors just let me know and I will help on resolving any issues!
