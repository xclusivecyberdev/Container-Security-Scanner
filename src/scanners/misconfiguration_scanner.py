"""Docker security misconfiguration scanner."""

import docker
import json
from typing import List, Dict, Any
from .base_scanner import BaseScanner, ScanResult


class MisconfigurationScanner(BaseScanner):
    """Scanner for Docker security misconfigurations."""

    def __init__(self):
        super().__init__("MisconfigurationScanner")
        self.client = docker.from_env()

    def scan(self, target: str, target_type: str = 'image') -> List[ScanResult]:
        """
        Scan Docker image or container for misconfigurations.

        Args:
            target: Image name/ID or container name/ID
            target_type: 'image' or 'container'

        Returns:
            List of ScanResult objects
        """
        self.clear_results()

        try:
            if target_type == 'image':
                self._scan_image(target)
            elif target_type == 'container':
                self._scan_container(target)
            else:
                raise ValueError(f"Invalid target type: {target_type}")

        except docker.errors.ImageNotFound:
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
                title='Misconfiguration Scan Error',
                description=f'Error scanning for misconfigurations: {str(e)}',
                remediation='Check target accessibility'
            ))

        return self.get_results()

    def _scan_image(self, image_name: str):
        """Scan image for misconfigurations."""
        image = self.client.images.get(image_name)
        config = image.attrs.get('Config', {})

        # Check for running as root
        self._check_user(config)

        # Check exposed ports
        self._check_exposed_ports(config)

        # Check environment variables
        self._check_environment(config)

        # Check healthcheck
        self._check_healthcheck(config)

        # Analyze Dockerfile instructions if available
        self._analyze_history(image)

    def _scan_container(self, container_name: str):
        """Scan running container for misconfigurations."""
        container = self.client.containers.get(container_name)
        config = container.attrs

        # Check security options
        self._check_security_options(config)

        # Check privileged mode
        self._check_privileged(config)

        # Check capabilities
        self._check_capabilities(config)

        # Check resource limits
        self._check_resource_limits(config)

        # Check network mode
        self._check_network_mode(config)

        # Check mounted volumes
        self._check_volumes(config)

        # Check PID namespace
        self._check_pid_mode(config)

    def _check_user(self, config: Dict):
        """Check if container runs as root."""
        user = config.get('User', '')

        if not user or user == 'root' or user == '0':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='Running as Root User',
                description='Container is configured to run as root user',
                remediation='Add USER directive in Dockerfile to run as non-root user',
                metadata={'user': user or 'root'}
            ))

    def _check_exposed_ports(self, config: Dict):
        """Check for exposed ports."""
        exposed_ports = config.get('ExposedPorts', {})

        # Check for dangerous ports
        dangerous_ports = {
            '22/tcp': 'SSH',
            '23/tcp': 'Telnet',
            '3389/tcp': 'RDP',
            '5432/tcp': 'PostgreSQL',
            '3306/tcp': 'MySQL',
            '27017/tcp': 'MongoDB',
            '6379/tcp': 'Redis',
            '9200/tcp': 'Elasticsearch'
        }

        for port, service in dangerous_ports.items():
            if port in exposed_ports:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='MEDIUM',
                    title=f'Exposed {service} Port',
                    description=f'Container exposes {service} port {port}',
                    remediation=f'Ensure {port} is properly secured or not exposed publicly',
                    metadata={'port': port, 'service': service}
                ))

    def _check_environment(self, config: Dict):
        """Check environment variables for sensitive data."""
        env_vars = config.get('Env', [])

        sensitive_patterns = [
            'PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API_KEY',
            'PRIVATE', 'CREDENTIAL', 'AUTH'
        ]

        for env in env_vars:
            if '=' in env:
                key, value = env.split('=', 1)
                for pattern in sensitive_patterns:
                    if pattern in key.upper() and value:
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity='HIGH',
                            title='Sensitive Data in Environment Variable',
                            description=f'Environment variable {key} may contain sensitive data',
                            remediation='Use Docker secrets or external secret management instead of environment variables',
                            metadata={'variable': key}
                        ))
                        break

    def _check_healthcheck(self, config: Dict):
        """Check for healthcheck configuration."""
        healthcheck = config.get('Healthcheck')

        if not healthcheck:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='Missing Healthcheck',
                description='Container does not have a healthcheck configured',
                remediation='Add HEALTHCHECK instruction to Dockerfile',
                metadata={'healthcheck': None}
            ))

    def _analyze_history(self, image):
        """Analyze image history for security issues."""
        history = image.history()

        for layer in history:
            created_by = layer.get('CreatedBy', '')

            # Check for ADD usage (should use COPY instead)
            if 'ADD' in created_by and 'http' not in created_by.lower():
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='LOW',
                    title='ADD Instruction Usage',
                    description='Image uses ADD instead of COPY',
                    remediation='Use COPY instead of ADD unless extracting archives',
                    metadata={'instruction': created_by[:100]}
                ))

            # Check for curl/wget without cleanup
            if ('curl' in created_by or 'wget' in created_by) and 'rm' not in created_by:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='LOW',
                    title='Downloaded Files Not Cleaned Up',
                    description='Downloaded files may not be cleaned up',
                    remediation='Clean up temporary files in the same layer',
                    metadata={'instruction': created_by[:100]}
                ))

    def _check_security_options(self, config: Dict):
        """Check security options."""
        host_config = config.get('HostConfig', {})
        security_opt = host_config.get('SecurityOpt', [])

        # Check for AppArmor
        has_apparmor = any('apparmor' in opt for opt in security_opt)
        # Check for SELinux
        has_selinux = any('selinux' in opt for opt in security_opt)
        # Check for seccomp
        has_seccomp = any('seccomp' in opt for opt in security_opt)

        if 'apparmor=unconfined' in security_opt or 'apparmor:unconfined' in security_opt:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='AppArmor Disabled',
                description='Container is running with AppArmor disabled',
                remediation='Enable AppArmor profile for the container',
                metadata={'security_opt': security_opt}
            ))

        if 'seccomp=unconfined' in security_opt or 'seccomp:unconfined' in security_opt:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='Seccomp Disabled',
                description='Container is running with seccomp disabled',
                remediation='Enable seccomp profile for the container',
                metadata={'security_opt': security_opt}
            ))

    def _check_privileged(self, config: Dict):
        """Check if container is running in privileged mode."""
        host_config = config.get('HostConfig', {})
        privileged = host_config.get('Privileged', False)

        if privileged:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='CRITICAL',
                title='Privileged Container',
                description='Container is running in privileged mode',
                remediation='Remove --privileged flag unless absolutely necessary',
                metadata={'privileged': True}
            ))

    def _check_capabilities(self, config: Dict):
        """Check for dangerous capabilities."""
        host_config = config.get('HostConfig', {})
        cap_add = host_config.get('CapAdd', [])

        dangerous_caps = {
            'SYS_ADMIN': 'Allows mounting filesystems and other admin operations',
            'SYS_MODULE': 'Allows loading kernel modules',
            'SYS_RAWIO': 'Allows raw I/O operations',
            'SYS_PTRACE': 'Allows tracing arbitrary processes',
            'NET_ADMIN': 'Allows network configuration',
            'DAC_OVERRIDE': 'Allows bypassing file permissions',
            'ALL': 'Grants all capabilities'
        }

        for cap in cap_add or []:
            cap_upper = cap.upper()
            if cap_upper in dangerous_caps:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='HIGH',
                    title=f'Dangerous Capability: {cap}',
                    description=dangerous_caps[cap_upper],
                    remediation=f'Remove {cap} capability unless required',
                    metadata={'capability': cap}
                ))

    def _check_resource_limits(self, config: Dict):
        """Check for resource limits."""
        host_config = config.get('HostConfig', {})

        memory = host_config.get('Memory', 0)
        cpu_quota = host_config.get('CpuQuota', 0)

        if memory == 0:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='No Memory Limit',
                description='Container has no memory limit set',
                remediation='Set memory limit with --memory flag',
                metadata={'memory_limit': None}
            ))

        if cpu_quota == 0:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='No CPU Limit',
                description='Container has no CPU limit set',
                remediation='Set CPU limit with --cpus or --cpu-quota flag',
                metadata={'cpu_limit': None}
            ))

    def _check_network_mode(self, config: Dict):
        """Check network mode."""
        host_config = config.get('HostConfig', {})
        network_mode = host_config.get('NetworkMode', '')

        if network_mode == 'host':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='Host Network Mode',
                description='Container is using host network mode',
                remediation='Use bridge or custom network instead of host mode',
                metadata={'network_mode': 'host'}
            ))

    def _check_volumes(self, config: Dict):
        """Check mounted volumes."""
        host_config = config.get('HostConfig', {})
        binds = host_config.get('Binds', [])

        sensitive_paths = [
            '/etc', '/var/run/docker.sock', '/root', '/home',
            '/proc', '/sys', '/dev', '/boot'
        ]

        for bind in binds or []:
            source = bind.split(':')[0] if ':' in bind else bind

            for sensitive_path in sensitive_paths:
                if source.startswith(sensitive_path):
                    severity = 'CRITICAL' if 'docker.sock' in source else 'HIGH'
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity=severity,
                        title=f'Sensitive Path Mounted: {sensitive_path}',
                        description=f'Container mounts sensitive host path: {source}',
                        remediation='Avoid mounting sensitive host paths',
                        metadata={'mount': bind, 'path': source}
                    ))
                    break

            # Check for read-write mounts
            if ':' in bind and not bind.endswith(':ro'):
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='LOW',
                    title='Read-Write Volume Mount',
                    description=f'Volume mounted as read-write: {bind}',
                    remediation='Mount volumes as read-only when possible using :ro flag',
                    metadata={'mount': bind}
                ))

    def _check_pid_mode(self, config: Dict):
        """Check PID namespace mode."""
        host_config = config.get('HostConfig', {})
        pid_mode = host_config.get('PidMode', '')

        if pid_mode == 'host':
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='Host PID Namespace',
                description='Container is using host PID namespace',
                remediation='Do not use --pid=host unless necessary',
                metadata={'pid_mode': 'host'}
            ))
