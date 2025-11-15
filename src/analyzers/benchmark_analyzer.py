"""Docker CIS Benchmark compliance analyzer."""

import docker
import os
from typing import List, Dict, Any
from ..scanners.base_scanner import BaseScanner, ScanResult


class DockerBenchmarkAnalyzer(BaseScanner):
    """
    Analyzer for Docker CIS Benchmark compliance.
    Based on CIS Docker Benchmark v1.6.0
    """

    def __init__(self):
        super().__init__("DockerBenchmarkAnalyzer")
        self.client = docker.from_env()

    def scan(self, target: str, target_type: str = 'image') -> List[ScanResult]:
        """
        Analyze Docker configuration against CIS Benchmark.

        Args:
            target: Image name/ID or container name/ID
            target_type: 'image' or 'container'

        Returns:
            List of ScanResult objects
        """
        self.clear_results()

        try:
            if target_type == 'image':
                self._scan_image_compliance(target)
            elif target_type == 'container':
                self._scan_container_compliance(target)

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
                title='Benchmark Scan Error',
                description=f'Error scanning benchmark compliance: {str(e)}',
                remediation='Check target accessibility'
            ))

        return self.get_results()

    def _scan_image_compliance(self, image_name: str):
        """Scan image for CIS Benchmark compliance."""
        image = self.client.images.get(image_name)
        config = image.attrs.get('Config', {})

        # 4.1 - Ensure a user for the container has been created
        self._check_4_1_user(config)

        # 4.2 - Ensure that containers use only trusted base images
        self._check_4_2_trusted_base(image)

        # 4.3 - Ensure that unnecessary packages are not installed
        self._check_4_3_minimal_packages(image)

        # 4.6 - Ensure that HEALTHCHECK instructions have been added
        self._check_4_6_healthcheck(config)

        # 4.7 - Ensure update instructions are not used alone
        self._check_4_7_update_instructions(image)

        # 4.9 - Ensure that ADD is not used instead of COPY
        self._check_4_9_add_usage(image)

        # 4.10 - Ensure secrets are not stored in Dockerfiles
        self._check_4_10_secrets(image)

    def _scan_container_compliance(self, container_name: str):
        """Scan container for CIS Benchmark compliance."""
        container = self.client.containers.get(container_name)
        config = container.attrs
        host_config = config.get('HostConfig', {})

        # 5.1 - Ensure that AppArmor profile is enabled
        self._check_5_1_apparmor(host_config)

        # 5.2 - Ensure that SELinux security options are set
        self._check_5_2_selinux(host_config)

        # 5.3 - Ensure that Linux kernel capabilities are restricted
        self._check_5_3_capabilities(host_config)

        # 5.4 - Ensure that privileged containers are not used
        self._check_5_4_privileged(host_config)

        # 5.5 - Ensure sensitive host system directories are not mounted
        self._check_5_5_host_mounts(host_config)

        # 5.6 - Ensure sshd is not run within containers
        self._check_5_6_sshd(container)

        # 5.7 - Ensure privileged ports are not mapped
        self._check_5_7_privileged_ports(host_config)

        # 5.9 - Ensure that the host's network namespace is not shared
        self._check_5_9_host_network(host_config)

        # 5.10 - Ensure that the memory usage for containers is limited
        self._check_5_10_memory_limit(host_config)

        # 5.11 - Ensure that CPU priority is set appropriately
        self._check_5_11_cpu_shares(host_config)

        # 5.12 - Ensure that the container's root filesystem is mounted as read-only
        self._check_5_12_readonly_rootfs(host_config)

        # 5.15 - Ensure that the host's process namespace is not shared
        self._check_5_15_pid_mode(host_config)

        # 5.16 - Ensure that the host's IPC namespace is not shared
        self._check_5_16_ipc_mode(host_config)

        # 5.25 - Ensure that the container is restricted from acquiring additional privileges
        self._check_5_25_no_new_privileges(host_config)

        # 5.28 - Ensure that the PIDs cgroup limit is used
        self._check_5_28_pids_limit(host_config)

        # 5.31 - Ensure that the Docker socket is not mounted
        self._check_5_31_docker_socket(host_config)

    def _check_4_1_user(self, config: Dict):
        """4.1 - Ensure a user for the container has been created."""
        user = config.get('User', '')

        if not user or user == 'root' or user == '0':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='CIS 4.1 - Container runs as root',
                description='Container does not specify a non-root user',
                remediation='Add USER directive to Dockerfile to run as non-root user',
                metadata={'benchmark': 'CIS 4.1', 'user': user or 'root'}
            ))

    def _check_4_2_trusted_base(self, image):
        """4.2 - Ensure that containers use only trusted base images."""
        tags = image.tags

        for tag in tags:
            # Check if using :latest
            if ':latest' in tag or ':' not in tag:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='MEDIUM',
                    title='CIS 4.2 - Using unversioned base image',
                    description='Image uses :latest or unversioned tag',
                    remediation='Use specific version tags for base images',
                    metadata={'benchmark': 'CIS 4.2', 'tag': tag}
                ))

    def _check_4_3_minimal_packages(self, image):
        """4.3 - Ensure that unnecessary packages are not installed."""
        # Check image size as a heuristic
        size = image.attrs.get('Size', 0)
        size_mb = size / (1024 * 1024)

        if size_mb > 500:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='CIS 4.3 - Large image size',
                description=f'Image size is {size_mb:.1f}MB, may contain unnecessary packages',
                remediation='Use minimal base images and multi-stage builds to reduce image size',
                metadata={'benchmark': 'CIS 4.3', 'size_mb': size_mb}
            ))

    def _check_4_6_healthcheck(self, config: Dict):
        """4.6 - Ensure that HEALTHCHECK instructions have been added."""
        healthcheck = config.get('Healthcheck')

        if not healthcheck:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='CIS 4.6 - Missing HEALTHCHECK',
                description='Container image does not define a healthcheck',
                remediation='Add HEALTHCHECK instruction to Dockerfile',
                metadata={'benchmark': 'CIS 4.6'}
            ))

    def _check_4_7_update_instructions(self, image):
        """4.7 - Ensure update instructions are not used alone."""
        history = image.history()

        for layer in history:
            created_by = layer.get('CreatedBy', '').lower()

            # Check for apt-get update without upgrade or install
            if 'apt-get update' in created_by and not ('install' in created_by or 'upgrade' in created_by):
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='MEDIUM',
                    title='CIS 4.7 - apt-get update used alone',
                    description='Found apt-get update without install or upgrade in same layer',
                    remediation='Combine update with install in same RUN instruction',
                    metadata={'benchmark': 'CIS 4.7', 'command': created_by[:100]}
                ))

    def _check_4_9_add_usage(self, image):
        """4.9 - Ensure that ADD is not used instead of COPY."""
        history = image.history()

        for layer in history:
            created_by = layer.get('CreatedBy', '')

            if 'ADD' in created_by.upper() and 'http' not in created_by.lower():
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='LOW',
                    title='CIS 4.9 - ADD instruction used',
                    description='Image uses ADD instruction instead of COPY',
                    remediation='Use COPY instead of ADD unless extracting archives',
                    metadata={'benchmark': 'CIS 4.9', 'command': created_by[:100]}
                ))

    def _check_4_10_secrets(self, image):
        """4.10 - Ensure secrets are not stored in Dockerfiles."""
        history = image.history()

        secret_keywords = ['password', 'secret', 'key', 'token', 'api_key']

        for layer in history:
            created_by = layer.get('CreatedBy', '').lower()

            for keyword in secret_keywords:
                if keyword in created_by and '=' in created_by:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title='CIS 4.10 - Potential secret in Dockerfile',
                        description=f'Found potential secret keyword "{keyword}" in build command',
                        remediation='Use build-time secrets or environment variables instead',
                        metadata={'benchmark': 'CIS 4.10', 'keyword': keyword}
                    ))
                    break

    def _check_5_1_apparmor(self, host_config: Dict):
        """5.1 - Ensure that AppArmor profile is enabled."""
        security_opt = host_config.get('SecurityOpt', [])

        if not security_opt or 'apparmor=unconfined' in security_opt:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='CIS 5.1 - AppArmor not enabled',
                description='Container does not have AppArmor profile enabled',
                remediation='Enable AppArmor profile for the container',
                metadata={'benchmark': 'CIS 5.1'}
            ))

    def _check_5_2_selinux(self, host_config: Dict):
        """5.2 - Ensure that SELinux security options are set."""
        security_opt = host_config.get('SecurityOpt', [])

        has_selinux = any('label' in opt for opt in security_opt)

        if not has_selinux:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='INFO',
                title='CIS 5.2 - SELinux options not set',
                description='Container does not have SELinux security options',
                remediation='Set SELinux labels if using SELinux',
                metadata={'benchmark': 'CIS 5.2'}
            ))

    def _check_5_3_capabilities(self, host_config: Dict):
        """5.3 - Ensure that Linux kernel capabilities are restricted."""
        cap_add = host_config.get('CapAdd', [])
        cap_drop = host_config.get('CapDrop', [])

        if cap_add and 'ALL' in [c.upper() for c in cap_add]:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='CIS 5.3 - All capabilities added',
                description='Container has all capabilities added',
                remediation='Add only necessary capabilities',
                metadata={'benchmark': 'CIS 5.3'}
            ))

        if not cap_drop:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='CIS 5.3 - No capabilities dropped',
                description='Container does not drop any capabilities',
                remediation='Drop unnecessary capabilities with --cap-drop',
                metadata={'benchmark': 'CIS 5.3'}
            ))

    def _check_5_4_privileged(self, host_config: Dict):
        """5.4 - Ensure that privileged containers are not used."""
        if host_config.get('Privileged', False):
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='CRITICAL',
                title='CIS 5.4 - Privileged container',
                description='Container is running in privileged mode',
                remediation='Remove --privileged flag',
                metadata={'benchmark': 'CIS 5.4'}
            ))

    def _check_5_5_host_mounts(self, host_config: Dict):
        """5.5 - Ensure sensitive host system directories are not mounted."""
        binds = host_config.get('Binds', [])

        sensitive_paths = [
            '/', '/boot', '/dev', '/etc', '/lib', '/proc', '/sys',
            '/usr', '/var/run'
        ]

        for bind in binds or []:
            source = bind.split(':')[0] if ':' in bind else bind

            for sensitive in sensitive_paths:
                if source == sensitive or source.startswith(sensitive + '/'):
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title=f'CIS 5.5 - Sensitive directory mounted: {sensitive}',
                        description=f'Container mounts sensitive host directory: {source}',
                        remediation='Avoid mounting sensitive host directories',
                        metadata={'benchmark': 'CIS 5.5', 'path': source}
                    ))
                    break

    def _check_5_6_sshd(self, container):
        """5.6 - Ensure sshd is not run within containers."""
        try:
            # Check if sshd process is running
            exec_result = container.exec_run('ps aux')
            if exec_result.exit_code == 0:
                output = exec_result.output.decode('utf-8', errors='ignore')
                if 'sshd' in output:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='MEDIUM',
                        title='CIS 5.6 - SSH daemon running',
                        description='Container is running SSH daemon',
                        remediation='Use docker exec instead of SSH for container access',
                        metadata={'benchmark': 'CIS 5.6'}
                    ))
        except Exception:
            pass

    def _check_5_7_privileged_ports(self, host_config: Dict):
        """5.7 - Ensure privileged ports are not mapped."""
        port_bindings = host_config.get('PortBindings', {})

        for container_port, bindings in (port_bindings or {}).items():
            for binding in bindings or []:
                host_port = binding.get('HostPort', '')
                if host_port and host_port.isdigit() and int(host_port) < 1024:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='MEDIUM',
                        title=f'CIS 5.7 - Privileged port mapped: {host_port}',
                        description=f'Container maps privileged port {host_port}',
                        remediation='Use non-privileged ports (>= 1024)',
                        metadata={'benchmark': 'CIS 5.7', 'port': host_port}
                    ))

    def _check_5_9_host_network(self, host_config: Dict):
        """5.9 - Ensure that the host's network namespace is not shared."""
        if host_config.get('NetworkMode') == 'host':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='CIS 5.9 - Host network mode',
                description='Container uses host network namespace',
                remediation='Use bridge or custom network instead of host mode',
                metadata={'benchmark': 'CIS 5.9'}
            ))

    def _check_5_10_memory_limit(self, host_config: Dict):
        """5.10 - Ensure that the memory usage for containers is limited."""
        memory = host_config.get('Memory', 0)

        if memory == 0:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='CIS 5.10 - No memory limit',
                description='Container has no memory limit',
                remediation='Set memory limit with --memory flag',
                metadata={'benchmark': 'CIS 5.10'}
            ))

    def _check_5_11_cpu_shares(self, host_config: Dict):
        """5.11 - Ensure that CPU priority is set appropriately."""
        cpu_shares = host_config.get('CpuShares', 0)

        if cpu_shares == 0:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='CIS 5.11 - No CPU shares set',
                description='Container has no CPU shares configured',
                remediation='Set CPU shares with --cpu-shares flag',
                metadata={'benchmark': 'CIS 5.11'}
            ))

    def _check_5_12_readonly_rootfs(self, host_config: Dict):
        """5.12 - Ensure that the container's root filesystem is mounted as read-only."""
        readonly_rootfs = host_config.get('ReadonlyRootfs', False)

        if not readonly_rootfs:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='CIS 5.12 - Root filesystem not read-only',
                description='Container root filesystem is writable',
                remediation='Use --read-only flag when possible',
                metadata={'benchmark': 'CIS 5.12'}
            ))

    def _check_5_15_pid_mode(self, host_config: Dict):
        """5.15 - Ensure that the host's process namespace is not shared."""
        if host_config.get('PidMode') == 'host':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='CIS 5.15 - Host PID namespace',
                description='Container shares host PID namespace',
                remediation='Do not use --pid=host',
                metadata={'benchmark': 'CIS 5.15'}
            ))

    def _check_5_16_ipc_mode(self, host_config: Dict):
        """5.16 - Ensure that the host's IPC namespace is not shared."""
        if host_config.get('IpcMode') == 'host':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='CIS 5.16 - Host IPC namespace',
                description='Container shares host IPC namespace',
                remediation='Do not use --ipc=host',
                metadata={'benchmark': 'CIS 5.16'}
            ))

    def _check_5_25_no_new_privileges(self, host_config: Dict):
        """5.25 - Ensure that the container is restricted from acquiring additional privileges."""
        security_opt = host_config.get('SecurityOpt', [])

        has_no_new_privs = any('no-new-privileges' in opt for opt in security_opt)

        if not has_no_new_privs:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='CIS 5.25 - no-new-privileges not set',
                description='Container can acquire new privileges',
                remediation='Use --security-opt=no-new-privileges',
                metadata={'benchmark': 'CIS 5.25'}
            ))

    def _check_5_28_pids_limit(self, host_config: Dict):
        """5.28 - Ensure that the PIDs cgroup limit is used."""
        pids_limit = host_config.get('PidsLimit', 0)

        if pids_limit == 0 or pids_limit == -1:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='CIS 5.28 - No PIDs limit',
                description='Container has no PIDs limit',
                remediation='Set PIDs limit with --pids-limit',
                metadata={'benchmark': 'CIS 5.28'}
            ))

    def _check_5_31_docker_socket(self, host_config: Dict):
        """5.31 - Ensure that the Docker socket is not mounted."""
        binds = host_config.get('Binds', [])

        for bind in binds or []:
            if 'docker.sock' in bind:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='CRITICAL',
                    title='CIS 5.31 - Docker socket mounted',
                    description='Container has access to Docker socket',
                    remediation='Do not mount /var/run/docker.sock',
                    metadata={'benchmark': 'CIS 5.31', 'mount': bind}
                ))
