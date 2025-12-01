import { LucideIcon } from 'lucide-react'

interface StatsCardProps {
  title: string
  value: number | string
  icon: LucideIcon
  color: 'primary' | 'danger' | 'warning' | 'success'
}

export default function StatsCard({
  title,
  value,
  icon: Icon,
  color,
}: StatsCardProps) {
  const colorClasses = {
    primary: 'bg-primary-50 text-primary-600 border-primary-200',
    danger: 'bg-danger-50 text-danger-600 border-danger-200',
    warning: 'bg-warning-50 text-warning-600 border-warning-200',
    success: 'bg-success-50 text-success-600 border-success-200',
  }

  return (
    <div className="card hover:shadow-md">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
        </div>
        <div
          className={`p-3 rounded-lg border-2 ${colorClasses[color]}`}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  )
}



