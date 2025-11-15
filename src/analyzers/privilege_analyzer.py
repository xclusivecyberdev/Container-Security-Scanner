"""Privilege escalation risk analyzer."""

import docker
import re
from typing import List, Dict, Any
from ..scanners.base_scanner import BaseScanner, ScanResult


class PrivilegeEscalationAnalyzer(BaseScanner):
    """Analyzer for privilege escalation risks in containers."""

    def __init__(self):
        super().__init__("PrivilegeEscalationAnalyzer")
        self.client = docker.from_env()

        # SUID/SGID binaries that are commonly exploited
        self.dangerous_suid_binaries = {
            'find', 'vim', 'nano', 'less', 'more', 'awk', 'gawk',
            'python', 'python2', 'python3', 'perl', 'ruby', 'php',
            'gcc', 'g++', 'make', 'ld', 'as',
            'nmap', 'tcpdump', 'wireshark',
            'docker', 'kubectl', 'crictl',
            'busybox', 'ash', 'dash',
        }

        # System binaries that should have SUID (normal)
        self.normal_suid_binaries = {
            'ping', 'su', 'sudo', 'passwd', 'chfn', 'chsh',
            'mount', 'umount', 'newgrp', 'gpasswd'
        }

    def scan(self, target: str, target_type: str = 'image') -> List[ScanResult]:
        """
        Analyze privilege escalation risks.

        Args:
            target: Image name/ID or container name/ID
            target_type: 'image' or 'container'

        Returns:
            List of ScanResult objects
        """
        self.clear_results()

        try:
            if target_type == 'image':
                image = self.client.images.get(target)
                self._analyze_image(image)
            elif target_type == 'container':
                container = self.client.containers.get(target)
                self._analyze_container(container)

        except docker.errors.NotFound:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='CRITICAL',
                title='Target Not Found',
                description=f'{target_type.capitalize()} {target} not found',
                remediation='Ensure the target exists'
            ))
        except Exception as e:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='Privilege Analysis Error',
                description=f'Error analyzing privileges: {str(e)}',
                remediation='Check target accessibility'
            ))

        return self.get_results()

    def _analyze_image(self, image):
        """Analyze image for privilege escalation risks."""
        # Check user configuration
        config = image.attrs.get('Config', {})
        user = config.get('User', '')

        # Check for SUID/SGID binaries in image
        self._check_suid_binaries(image)

        # Check for sudo/su access
        self._check_sudo_access(image)

        # Check for writable sensitive files
        self._check_writable_files(image)

        # Analyze capabilities if container
        # (limited for images, mainly check config)

    def _analyze_container(self, container):
        """Analyze running container for privilege escalation risks."""
        config = container.attrs

        # Check all image-based risks
        self._analyze_image(self.client.images.get(container.image.id))

        # Check container-specific settings
        host_config = config.get('HostConfig', {})

        # Check privileged mode
        if host_config.get('Privileged', False):
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='CRITICAL',
                title='Privileged Container - Full Escalation Risk',
                description='Container runs in privileged mode, allowing full host access',
                remediation='Remove --privileged flag. Use specific capabilities instead.',
                metadata={'privileged': True}
            ))

        # Check dangerous capabilities
        self._check_dangerous_capabilities(host_config)

        # Check for host namespace sharing
        self._check_namespace_sharing(host_config)

        # Check for container breakout vectors
        self._check_breakout_vectors(config)

    def _check_suid_binaries(self, image):
        """Check for SUID/SGID binaries in the image."""
        try:
            # Run find command to locate SUID/SGID files
            container = self.client.containers.create(
                image.id,
                command='sh -c "find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null"',
                detach=True
            )
            container.start()
            exit_code = container.wait(timeout=30)
            output = container.logs().decode('utf-8', errors='ignore')
            container.remove()

            if output:
                suid_files = [f.strip() for f in output.split('\n') if f.strip()]

                for filepath in suid_files:
                    binary_name = filepath.split('/')[-1]

                    # Check if it's a dangerous SUID binary
                    if binary_name in self.dangerous_suid_binaries:
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity='CRITICAL',
                            title=f'Dangerous SUID Binary: {binary_name}',
                            description=f'Found SUID binary that can be exploited for privilege escalation: {filepath}',
                            remediation=f'Remove SUID bit from {filepath} or remove the binary',
                            metadata={'binary': filepath, 'type': 'suid'}
                        ))
                    elif binary_name not in self.normal_suid_binaries:
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity='MEDIUM',
                            title=f'Unusual SUID Binary: {binary_name}',
                            description=f'Found unusual SUID/SGID binary: {filepath}',
                            remediation=f'Review if SUID bit is necessary for {filepath}',
                            metadata={'binary': filepath, 'type': 'suid'}
                        ))

        except Exception:
            pass

    def _check_sudo_access(self, image):
        """Check for sudo configuration and passwordless sudo."""
        try:
            # Check if sudo is installed and configured
            container = self.client.containers.create(
                image.id,
                command='sh -c "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null"',
                detach=True
            )
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8', errors='ignore')
            container.remove()

            if output:
                # Check for NOPASSWD
                if 'NOPASSWD' in output:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title='Passwordless Sudo Configuration',
                        description='Found NOPASSWD configuration in sudoers',
                        remediation='Remove NOPASSWD from sudoers or ensure proper user restrictions',
                        metadata={'config': 'sudoers_nopasswd'}
                    ))

                # Check for ALL=(ALL:ALL)
                if re.search(r'ALL\s*=\s*\(ALL:ALL\)', output):
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title='Unrestricted Sudo Access',
                        description='Found unrestricted sudo access configuration',
                        remediation='Restrict sudo access to specific commands',
                        metadata={'config': 'sudoers_all'}
                    ))

        except Exception:
            pass

    def _check_writable_files(self, image):
        """Check for world-writable sensitive files."""
        try:
            # Check for world-writable files in sensitive locations
            container = self.client.containers.create(
                image.id,
                command='sh -c "find /etc /usr /bin /sbin -type f -perm -002 2>/dev/null | head -20"',
                detach=True
            )
            container.start()
            container.wait(timeout=20)
            output = container.logs().decode('utf-8', errors='ignore')
            container.remove()

            if output:
                writable_files = [f.strip() for f in output.split('\n') if f.strip()]

                for filepath in writable_files:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title='World-Writable Sensitive File',
                        description=f'Found world-writable file in sensitive location: {filepath}',
                        remediation=f'Fix permissions on {filepath} (remove write for others)',
                        metadata={'file': filepath, 'type': 'writable'}
                    ))

        except Exception:
            pass

    def _check_dangerous_capabilities(self, host_config: Dict):
        """Check for dangerous Linux capabilities."""
        cap_add = host_config.get('CapAdd', [])

        escalation_capabilities = {
            'CAP_SYS_ADMIN': {
                'severity': 'CRITICAL',
                'description': 'Allows performing system administration operations, including mounting filesystems',
                'risk': 'Container escape via mount operations'
            },
            'CAP_SYS_PTRACE': {
                'severity': 'HIGH',
                'description': 'Allows tracing arbitrary processes and reading/writing process memory',
                'risk': 'Process injection and privilege escalation'
            },
            'CAP_SYS_MODULE': {
                'severity': 'CRITICAL',
                'description': 'Allows loading and unloading kernel modules',
                'risk': 'Kernel-level code execution'
            },
            'CAP_DAC_OVERRIDE': {
                'severity': 'HIGH',
                'description': 'Allows bypassing file read, write, and execute permission checks',
                'risk': 'Unrestricted file system access'
            },
            'CAP_DAC_READ_SEARCH': {
                'severity': 'MEDIUM',
                'description': 'Allows bypassing file read permission checks',
                'risk': 'Read access to any file'
            },
            'CAP_SYS_RAWIO': {
                'severity': 'HIGH',
                'description': 'Allows raw I/O port access',
                'risk': 'Hardware-level access and exploitation'
            },
            'CAP_NET_ADMIN': {
                'severity': 'MEDIUM',
                'description': 'Allows network configuration',
                'risk': 'Network manipulation and sniffing'
            },
        }

        for cap in cap_add or []:
            cap_upper = cap.upper()
            if not cap_upper.startswith('CAP_'):
                cap_upper = f'CAP_{cap_upper}'

            if cap_upper in escalation_capabilities:
                info = escalation_capabilities[cap_upper]
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity=info['severity'],
                    title=f'Dangerous Capability: {cap}',
                    description=f"{info['description']}. Risk: {info['risk']}",
                    remediation=f'Remove {cap} capability unless absolutely required',
                    metadata={'capability': cap, 'risk': info['risk']}
                ))

    def _check_namespace_sharing(self, host_config: Dict):
        """Check for host namespace sharing."""
        namespace_checks = {
            'PidMode': {
                'value': 'host',
                'severity': 'HIGH',
                'title': 'Host PID Namespace Sharing',
                'description': 'Container shares PID namespace with host',
                'risk': 'Can view and interact with all host processes'
            },
            'IpcMode': {
                'value': 'host',
                'severity': 'MEDIUM',
                'title': 'Host IPC Namespace Sharing',
                'description': 'Container shares IPC namespace with host',
                'risk': 'Can access host IPC resources'
            },
            'NetworkMode': {
                'value': 'host',
                'severity': 'MEDIUM',
                'title': 'Host Network Namespace Sharing',
                'description': 'Container shares network namespace with host',
                'risk': 'Full access to host network stack'
            },
        }

        for mode, info in namespace_checks.items():
            if host_config.get(mode) == info['value']:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity=info['severity'],
                    title=info['title'],
                    description=f"{info['description']}. Risk: {info['risk']}",
                    remediation=f"Do not use --{mode.lower()}=host unless absolutely necessary",
                    metadata={'namespace': mode, 'risk': info['risk']}
                ))

    def _check_breakout_vectors(self, config: Dict):
        """Check for known container breakout vectors."""
        host_config = config.get('HostConfig', {})
        binds = host_config.get('Binds', [])

        # Check for Docker socket mount
        for bind in binds or []:
            if '/var/run/docker.sock' in bind:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='CRITICAL',
                    title='Docker Socket Mounted - Container Escape Vector',
                    description='Docker socket is mounted, allowing full Docker API access from container',
                    remediation='Remove docker.sock mount. Use Docker-in-Docker if needed.',
                    metadata={'mount': bind, 'risk': 'full_host_control'}
                ))

        # Check for cgroup mounts
        for bind in binds or []:
            if '/sys/fs/cgroup' in bind and not bind.endswith(':ro'):
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='HIGH',
                    title='Writable Cgroup Mount - Escape Vector',
                    description='Writable cgroup mount can be exploited for container escape',
                    remediation='Mount cgroup as read-only or remove mount',
                    metadata={'mount': bind, 'risk': 'cgroup_escape'}
                ))

        # Check for proc/sys mounts
        for bind in binds or []:
            if ('/proc' in bind or '/sys' in bind) and not bind.endswith(':ro'):
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='HIGH',
                    title='Writable /proc or /sys Mount',
                    description='Writable /proc or /sys mount can be exploited',
                    remediation='Mount as read-only or avoid mounting',
                    metadata={'mount': bind, 'risk': 'kernel_interface_manipulation'}
                ))
