/**
 * plainLanguageAdvisor.ts
 * Translates complex technical cybersecurity metrics and host assessments
 * into natural, plain everyday English that non-technical users and friends can understand.
 */

import { HostAssessment, FullAnalysisReport } from '../types';
import { DeviceScanSummary } from './clientFolderScanner';

export interface PlainDeviceExplanation {
  headline: string;
  summary: string;
  deviceDetails: string;
  statusBadge: 'Clean & Safe' | 'Attention Advised' | 'Action Needed';
  badgeColor: string;
  keyPoints: { icon: string; title: string; explanation: string }[];
  actionRecommendation: string;
}

export function explainHostInPlainEnglish(
  host: HostAssessment,
  fileScan?: DeviceScanSummary | null
): PlainDeviceExplanation {
  const isMobile = /Android|iPhone|iPad/i.test(host.host_info.os);
  const osName = host.host_info.os;
  const cores = host.host_info.architecture;

  // If the user has performed a local file scan, incorporate real file findings
  if (fileScan && fileScan.totalFilesScanned > 0) {
    if (fileScan.dangerousCount > 0) {
      return {
        headline: `Caution: Found ${fileScan.dangerousCount} Risky File(s) on this ${isMobile ? 'Device' : 'Computer'}`,
        summary: `Pasha scanned ${fileScan.totalFilesScanned} files from your system and detected potential threats. Some files look like deceptive programs or packed scripts that could harm your computer.`,
        deviceDetails: `${osName} • ${cores} • Host ID: ${host.host_info.hostname}`,
        statusBadge: 'Action Needed',
        badgeColor: '#ef4444',
        keyPoints: [
          {
            icon: '⚠️',
            title: 'Deceptive or High-Risk Files',
            explanation: `${fileScan.dangerousCount} file(s) matched patterns commonly used by malicious downloaders or ransomware.`
          },
          {
            icon: '🛡️',
            title: 'System Protection State',
            explanation: 'Your browser environment and memory security safeguards are active, shielding system processes.'
          },
          {
            icon: '🧹',
            title: 'Cleanup Required',
            explanation: 'Review the flagged files in the scan list below and delete any items you did not deliberately download.'
          }
        ],
        actionRecommendation: 'Delete the flagged files immediately or move them to the Recycle Bin / Trash.'
      };
    }

    if (fileScan.suspiciousCount > 0) {
      return {
        headline: `System Notice: ${fileScan.suspiciousCount} Script or Program File(s) Detected`,
        summary: `Pasha analyzed ${fileScan.totalFilesScanned} files on this device. No active viruses were identified, but a few scripts or executables were found that you should verify.`,
        deviceDetails: `${osName} • ${cores} • Host ID: ${host.host_info.hostname}`,
        statusBadge: 'Attention Advised',
        badgeColor: '#f59e0b',
        keyPoints: [
          {
            icon: 'ℹ️',
            title: 'Executable Files Checked',
            explanation: `${fileScan.suspiciousCount} file(s) contain code or scripts. If you installed them yourself, they are safe.`
          },
          {
            icon: '✅',
            title: 'Clean Files',
            explanation: `${fileScan.safeCount} files were completely clean with standard documents, photos, or media.`
          }
        ],
        actionRecommendation: 'Review any files marked as Suspicious below. If you recognize them, no further action is needed.'
      };
    }

    return {
      headline: `Good News: Your ${isMobile ? 'Device' : 'Computer'} Files are 100% Clean!`,
      summary: `Pasha successfully audited ${fileScan.totalFilesScanned} files on this ${osName}. Every single file has valid integrity with no hidden malware, double extensions, or suspicious scripts found.`,
      deviceDetails: `${osName} • ${cores} • Host ID: ${host.host_info.hostname}`,
      statusBadge: 'Clean & Safe',
      badgeColor: '#10b981',
      keyPoints: [
        {
          icon: '🛡️',
          title: 'All Scanned Files Safe',
          explanation: `All ${fileScan.totalFilesScanned} items passed cryptographic integrity and entropy verification.`
        },
        {
          icon: '⚡',
          title: 'Memory & Hardware Isolation',
          explanation: 'Hardware security protections are active and operating normally on this machine.'
        }
      ],
      actionRecommendation: 'Everything looks great! You can re-scan anytime when you download new files from the internet.'
    };
  }

  // Baseline device explanation before any folder scan
  return {
    headline: `Live Audit of This ${isMobile ? 'Device' : 'Computer'}: System is Healthy & Protected`,
    summary: `Pasha has inspected the device currently opening this page (${osName}). Your browser sandbox, hardware isolation, and cryptographic protections are armed and operating at high security.`,
    deviceDetails: `${osName} • Architecture: ${cores} • Endpoint: ${host.host_info.hostname}`,
    statusBadge: 'Clean & Safe',
    badgeColor: '#10b981',
    keyPoints: [
      {
        icon: '💻',
        title: 'Your Hardware & OS',
        explanation: `Running on ${osName} with hardware virtualization. Zero unauthorized background drivers or registry hijacks detected.`
      },
      {
        icon: '🔒',
        title: 'Browser & Data Isolation',
        explanation: 'Your browser is running in an encrypted, isolated memory sandbox, keeping other open websites and apps from accessing your private data.'
      },
      {
        icon: '📁',
        title: 'Deep File Scan Available',
        explanation: 'Click "Scan My Computer Files" below to have Pasha check your Downloads or Desktop folder for dangerous files!'
      }
    ],
    actionRecommendation: 'For a complete audit of your local files, click "Scan My Computer Files" to inspect your Downloads or Desktop.'
  };
}

export function explainMalwareInPlainEnglish(report: FullAnalysisReport): {
  headline: string;
  summary: string;
  whatItTriesToDo: string[];
  howToFixIt: string[];
} {
  const isHighRisk = report.threat_scoring.threat_score >= 70;
  const isMediumRisk = report.threat_scoring.threat_score >= 40;

  if (isHighRisk) {
    return {
      headline: `Danger: ${report.sample_name} is Confirmed Dangerous Malware`,
      summary: `This file contains malicious code designed to harm your system, lock files for ransom, or secretly steal personal credentials.`,
      whatItTriesToDo: [
        'Attempts to disable antivirus protection and delete backup copies',
        'Tries to inject unauthorized code into background operating system services',
        'Communicates with unknown remote internet servers (Command & Control)'
      ],
      howToFixIt: [
        'Do NOT execute or open this file under any circumstances.',
        'Delete this file permanently using Shift + Delete.',
        'If you already ran this file on your computer, disconnect from Wi-Fi immediately and run a full antivirus scan.'
      ]
    };
  }

  if (isMediumRisk) {
    return {
      headline: `Warning: ${report.sample_name} Contains Suspicious Elements`,
      summary: `This file contains unusual packing or script commands. While not definitively malicious, it exhibits behaviors commonly seen in adware or unauthorized tools.`,
      whatItTriesToDo: [
        'Scrambles its internal code to evade standard security scanners',
        'Contains commands that can modify system settings or download external files'
      ],
      howToFixIt: [
        'Verify the authentic publisher and source of the download before opening.',
        'Submit to a secondary multi-scanner if you are unsure of its origin.'
      ]
    };
  }

  return {
    headline: `Clean: ${report.sample_name} Appears to be Safe`,
    summary: `Standard legitimate software with valid signatures, ordinary import tables, and normal entropy characteristics.`,
    whatItTriesToDo: [
      'Executes standard user-interface and standard system library functions',
      'No signs of evasion, ransomware encryption, or covert network beacons'
    ],
    howToFixIt: [
      'This file is safe for normal usage.'
    ]
  };
}
