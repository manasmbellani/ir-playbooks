"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_var_log_files' block
    list_var_log_files(container=container)

    return

@phantom.playbook_block()
def list_var_log_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_var_log_files() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "command": "find /var/log -ipath \"*auth*\" 2>/dev/null | tr -s \"\\n\" \",\"",
        "ip_hostname": "34.67.88.64",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="list_var_log_files", assets=["forensics-instance"], callback=get_auth_log_file)

    return


@phantom.playbook_block()
def get_auth_log_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_auth_log_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # get auth.log file which contains authentication attempts
    ################################################################################

    parameters = []

    parameters.append({
        "file_path": "/var/log/auth.log",
        "ip_hostname": "34.67.88.64",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="get_auth_log_file", assets=["forensics-instance"], callback=get_auditd_rules_file)

    return


@phantom.playbook_block()
def get_auditd_rules_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_auditd_rules_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "ip_hostname": "34.67.88.64",
        "file_path": "/etc/audit/audit.rules",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="get_auditd_rules_file", assets=["forensics-instance"], callback=get_audit_logs)

    return


@phantom.playbook_block()
def get_audit_logs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_audit_logs() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "ip_hostname": "34.67.88.64",
        "file_path": "/var/log/audit/audit.log",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="get_audit_logs", assets=["forensics-instance"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return