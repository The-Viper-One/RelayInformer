import getpass
import typer

from impacket import tds

from relayinformer.logger import logger, OBJ_EXTRA_FMT
from relayinformer.informers.MssqlInformer import MssqlInformer

app = typer.Typer()

COMMAND_NAME = "mssql"
HELP = "Check MSSQL servers"

DIRECT_TARGET_PANEL = "Direct Targeting"
AUTH_PANEL = "Authentication"
RUNTIME_PANEL = "Runtime"


# -----------------------------
# Colour helpers
# -----------------------------
def _colour_state(state: str) -> str:
    state_lower = state.lower()

    if state_lower == "required":
        return f"[green]{state}[/]"

    if state_lower == "allowed":
        return f"[yellow]{state}[/]"

    if state_lower == "off":
        return f"[red]{state}[/]"

    return state


def _vuln_tag(is_vulnerable: bool) -> str:

    if not is_vulnerable:
        return ""

    return " ([yellow]VULNERABLE[/])"



# -----------------------------
def _report_mssql_findings(
    endpoint: str,
    enc_state: str,
    epa_state: str,
    enc_vulnerable: bool,
    epa_vulnerable: bool,
):
    logger.info(
        f"[{endpoint}] (MSSQL) Transport Encryption : {_colour_state(enc_state)}"
        f"{_vuln_tag(enc_vulnerable)}",
        extra=OBJ_EXTRA_FMT,
    )

    logger.info(
        f"[{endpoint}] (MSSQL) EPA Channel Binding  : {_colour_state(epa_state)}"
        f"{_vuln_tag(epa_vulnerable)}",
        extra=OBJ_EXTRA_FMT,
    )


# -----------------------------
@app.callback(invoke_without_command=True, no_args_is_help=True)
def main(
    ctx: typer.Context,
    target: str = typer.Option(..., "--target", "-t", help="Target hostname or IP address", rich_help_panel=DIRECT_TARGET_PANEL),
    user: str = typer.Option(..., "--user", "-u", help="Username in format [domain/]username", rich_help_panel=AUTH_PANEL),
    password: str | None = typer.Option(None, "--password", "-p", help="Password for authentication", rich_help_panel=AUTH_PANEL),
    hashes: str | None = typer.Option(None, "--hashes", help="NTLM hashes in format LMHASH:NTHASH", rich_help_panel=AUTH_PANEL),
    port: int = typer.Option(1433, "--port", help="Target MSSQL port", rich_help_panel=RUNTIME_PANEL),
):

    try:
        MssqlInformer.parse_domain_user(user)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    endpoint = f"{target}:{port}"

    logger.info(
        f"Testing EPA enforcement level for MSSQL service at {endpoint} as {user}"
    )

    if password is None and hashes is None:
        password = getpass.getpass(prompt="Password: ")

    try:
        with MssqlInformer(target, user, port) as informer:

            encryption_setting = informer.check_encryption_requirements()

            if not informer.prereq_check(password, hashes, None, encryption_setting):
                logger.error("Prereq check failed, check credentials and try again")
                raise typer.Exit(1)

            # -----------------------------
            # ENCRYPTION REQUIRED
            # -----------------------------
            if encryption_setting == tds.TDS_ENCRYPT_REQ:

                logger.info("Running encrypted EPA channel binding checks")

                bogus_cb = informer.test_epa_with_bogus_channel_binding(password, hashes, None)

                if bogus_cb == "untrusted_domain":
                    missing_cb = informer.test_epa_with_missing_channel_binding(password, hashes, None)

                    if missing_cb == "untrusted_domain":
                        _report_mssql_findings(endpoint, "Required", "Required", False, False)

                    else:
                        _report_mssql_findings(endpoint, "Required", "Allowed", False, True)
                        raise typer.Exit(1)

                else:
                    _report_mssql_findings(endpoint, "Required", "Off", False, True)
                    raise typer.Exit(1)

            # -----------------------------
            # ENCRYPTION OFF
            # -----------------------------
            elif encryption_setting == tds.TDS_ENCRYPT_OFF:

                logger.info("Running unencrypted EPA channel binding checks")

                bogus_ts = informer.test_epa_with_bogus_target_service(password, hashes, None)

                if bogus_ts == "untrusted_domain":
                    missing_ts = informer.test_epa_with_missing_target_service(password, hashes, None)

                    if missing_ts == "untrusted_domain":
                        _report_mssql_findings(endpoint, "Off", "Required", True, False)

                    else:
                        _report_mssql_findings(endpoint, "Off", "Allowed", True, True)
                        raise typer.Exit(1)

                else:
                    _report_mssql_findings(endpoint, "Off", "Off", True, True)
                    raise typer.Exit(1)

            else:
                logger.error(f"[{endpoint}] (MSSQL) Transport Encryption : Unknown")
                logger.error(f"[{endpoint}] (MSSQL) EPA Channel Binding  : Unknown")
                raise typer.Exit(1)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        raise typer.Exit(0)

    except typer.Exit:
        raise

    except Exception as e:
        logger.error(f"Exception during MSSQL EPA testing: {str(e)}")
        raise typer.Exit(1)
