"""Provisioner abstraction.

A provisioner is responsible for giving a scan module a place to execute.
Today the Docker provisioner is real; cloud-VM and K8s are deliberate
placeholders so the UI and runner already speak to the same interface.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ExecResult:
    ok: bool
    stdout: str
    stderr: str
    ref: str | None = None  # container id / vm id / pod name


class Provisioner:
    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def run(self, image: str, command: list[str], timeout: int,
            labels: list[str] | None = None) -> ExecResult:
        raise NotImplementedError


class DockerProvisioner(Provisioner):
    """Runs a tool inside an ephemeral `docker run --rm` container."""

    name = "docker"

    def __init__(self, network: str = "bridge"):
        self.network = network

    def available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def run(self, image: str, command: list[str], timeout: int,
            labels: list[str] | None = None) -> ExecResult:
        cmd = ["docker", "run", "--rm", "--network", self.network,
               *(labels or []), image, *command]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return ExecResult(
                ok=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                ref=image,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(ok=False, stdout="", stderr=f"timeout after {timeout}s")
        except Exception as exc:  # noqa: BLE001
            return ExecResult(ok=False, stdout="", stderr=str(exc))


class CloudVMProvisioner(Provisioner):
    """Ephemeral AWS EC2 instance per scan (boto3 + SSM).

    Flow:
      1. Launch a Kali/tools AMI in the configured isolated subnet + SG, tagged
         TempleGuard (and with the engagement/client labels for traceability).
      2. Wait for the instance + SSM agent to be ready.
      3. Run the tool command via SSM RunShellScript, poll for completion.
      4. Terminate the instance.

    Disabled unless boto3 is installed AND region/AMI/subnet are configured AND
    credentials resolve. Untested without a live AWS account.
    Bring-your-own-cloud (assume-role into the client account) is a config swap:
    create the boto3 session from assumed-role credentials instead of the default
    chain.
    """

    name = "cloud_vm"

    def __init__(self):
        from ..config import settings
        self.cfg = settings

    def _session(self):
        try:
            import boto3  # noqa: F401
        except ImportError:
            return None
        if not (self.cfg.aws_region and self.cfg.aws_kali_ami and self.cfg.aws_subnet_id):
            return None
        import boto3
        try:
            sess = boto3.session.Session(region_name=self.cfg.aws_region)
            if sess.get_credentials() is None:
                return None
            return sess
        except Exception:
            return None

    def available(self) -> bool:
        return self._session() is not None

    def _parse_tags(self, labels: list[str] | None) -> list[dict]:
        tags = [{"Key": "TempleGuard", "Value": "true"}]
        for i, tok in enumerate(labels or []):
            if tok == "--label" and i + 1 < len(labels) and "=" in labels[i + 1]:
                k, v = labels[i + 1].split("=", 1)
                tags.append({"Key": k.replace("tg.", "tg-"), "Value": v})
        return tags

    def run(self, image: str, command: list[str], timeout: int,
            labels: list[str] | None = None) -> ExecResult:
        sess = self._session()
        if sess is None:
            return ExecResult(ok=False, stdout="",
                              stderr="cloud_vm not configured (need boto3 + "
                                     "TG_AWS_REGION/AMI/SUBNET + credentials)")
        ec2 = sess.client("ec2")
        ssm = sess.client("ssm")
        instance_id = None
        try:
            spec = {
                "ImageId": self.cfg.aws_kali_ami,
                "InstanceType": self.cfg.aws_instance_type,
                "MaxCount": 1, "MinCount": 1,
                "SubnetId": self.cfg.aws_subnet_id,
                "TagSpecifications": [{"ResourceType": "instance",
                                       "Tags": self._parse_tags(labels)}],
            }
            if self.cfg.aws_security_group_id:
                spec["SecurityGroupIds"] = [self.cfg.aws_security_group_id]
            if self.cfg.aws_key_name:
                spec["KeyName"] = self.cfg.aws_key_name
            if self.cfg.aws_iam_instance_profile:
                spec["IamInstanceProfile"] = {"Name": self.cfg.aws_iam_instance_profile}

            instance_id = ec2.run_instances(**spec)["Instances"][0]["InstanceId"]
            ec2.get_waiter("instance_status_ok").wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 15, "MaxAttempts": max(4, timeout // 15)})

            cmd = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [" ".join(command)]},
                TimeoutSeconds=min(timeout, 2400))
            cmd_id = cmd["Command"]["CommandId"]
            ssm.get_waiter("command_executed").wait(
                CommandId=cmd_id, InstanceId=instance_id,
                WaiterConfig={"Delay": 10, "MaxAttempts": max(4, timeout // 10)})
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            return ExecResult(ok=inv.get("Status") == "Success",
                              stdout=inv.get("StandardOutputContent", ""),
                              stderr=inv.get("StandardErrorContent", ""),
                              ref=instance_id)
        except Exception as exc:  # noqa: BLE001
            return ExecResult(ok=False, stdout="", stderr=str(exc), ref=instance_id)
        finally:
            if instance_id:
                try:
                    ec2.terminate_instances(InstanceIds=[instance_id])
                except Exception:
                    pass


class K8sProvisioner(Provisioner):
    """PLACEHOLDER — run each scan as a Kubernetes Job for high concurrency."""

    name = "k8s"

    def available(self) -> bool:
        return False

    def run(self, image: str, command: list[str], timeout: int,
            labels: list[str] | None = None) -> ExecResult:
        return ExecResult(
            ok=False,
            stdout="",
            stderr="k8s provisioner not yet implemented — see roadmap",
        )


def get_provisioner(name: str, network: str = "bridge") -> Provisioner:
    return {
        "docker": DockerProvisioner(network),
        "cloud_vm": CloudVMProvisioner(),
        "k8s": K8sProvisioner(),
    }.get(name, DockerProvisioner(network))
