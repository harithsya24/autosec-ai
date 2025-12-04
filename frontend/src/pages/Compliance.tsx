import { useState } from 'react'
import { FileText, Download, Calendar } from 'lucide-react'
import { complianceService } from '../services/api'
import type { ComplianceReport } from '../types'

export default function Compliance() {
  const [reportType, setReportType] = useState<'soc2' | 'gdpr' | 'hipaa' | 'custom'>('soc2')
  const [startDate, setStartDate] = useState(
    new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  )
  const [endDate, setEndDate] = useState(new Date().toISOString().split('T')[0])
  const [generating, setGenerating] = useState(false)
  const [report, setReport] = useState<ComplianceReport | null>(null)

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const data = await complianceService.generateReport(reportType, startDate, endDate)
      setReport(data)
    } catch (error) {
      console.error('Error generating report:', error)
      alert('Failed to generate report. Make sure the backend is running.')
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = () => {
    if (!report) return

    const content = `
# ${report.type.toUpperCase()} Compliance Report

**Period:** ${new Date(report.period_start).toLocaleDateString()} - ${new Date(report.period_end).toLocaleDateString()}
**Generated:** ${new Date(report.generated_at).toLocaleString()}

## Executive Summary

${report.summary}

## Metrics

- Total Incidents: ${report.metrics.total_incidents}
- Incidents Resolved: ${report.metrics.incidents_resolved}
- False Positives: ${report.metrics.false_positives}
- Average Response Time: ${report.metrics.average_response_time}ms
- Actions Taken: ${report.metrics.actions_taken}
- Actions Approved: ${report.metrics.actions_approved}
- Actions Rejected: ${report.metrics.actions_rejected}

${report.sections.map((section, idx) => `
## ${section.title}

${section.content}

### Findings
${section.findings.map((f) => `- ${f}`).join('\n')}

### Recommendations
${section.recommendations.map((r) => `- ${r}`).join('\n')}
`).join('\n')}
    `.trim()

    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `compliance-report-${report.type}-${Date.now()}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Compliance Reporting</h1>
        <p className="mt-2 text-gray-600">
          Generate automated compliance reports for auditing
        </p>
      </div>

      {/* Report Generator */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Generate Report</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Report Type
            </label>
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value as any)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="soc2">SOC 2</option>
              <option value="gdpr">GDPR</option>
              <option value="hipaa">HIPAA</option>
              <option value="custom">Custom</option>
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Start Date
              </label>
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                End Date
              </label>
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>

          <button
            onClick={handleGenerate}
            disabled={generating}
            className="btn-primary"
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Generated Report */}
      {report && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">
              {report.type.toUpperCase()} Compliance Report
            </h2>
            <button onClick={handleDownload} className="btn-secondary">
              <Download className="h-4 w-4 mr-2 inline" />
              Download
            </button>
          </div>

          <div className="space-y-6">
            {/* Summary */}
            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Executive Summary</h3>
              <p className="text-gray-700">{report.summary}</p>
            </div>

            {/* Metrics */}
            <div>
              <h3 className="font-semibold text-gray-900 mb-3">Key Metrics</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-sm text-gray-600">Total Incidents</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {report.metrics.total_incidents}
                  </p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-sm text-gray-600">Resolved</p>
                  <p className="text-2xl font-bold text-success-600">
                    {report.metrics.incidents_resolved}
                  </p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-sm text-gray-600">False Positives</p>
                  <p className="text-2xl font-bold text-warning-600">
                    {report.metrics.false_positives}
                  </p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-sm text-gray-600">Avg Response</p>
                  <p className="text-2xl font-bold text-primary-600">
                    {report.metrics.average_response_time}ms
                  </p>
                </div>
              </div>
            </div>

            {/* Sections */}
            {report.sections.map((section, idx) => (
              <div key={idx} className="border-t border-gray-200 pt-6">
                <h3 className="font-semibold text-gray-900 mb-3">{section.title}</h3>
                <p className="text-gray-700 mb-4">{section.content}</p>

                {section.findings.length > 0 && (
                  <div className="mb-4">
                    <h4 className="font-medium text-gray-900 mb-2">Findings</h4>
                    <ul className="list-disc list-inside space-y-1 text-gray-700">
                      {section.findings.map((finding, fIdx) => (
                        <li key={fIdx}>{finding}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {section.recommendations.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Recommendations</h4>
                    <ul className="list-disc list-inside space-y-1 text-gray-700">
                      {section.recommendations.map((rec, rIdx) => (
                        <li key={rIdx}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}





