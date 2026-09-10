interface StatCardProps {
  title: string;
  value: number;
  icon: string;
  description?: string;
}

export default function StatCard({
  title,
  value,
  icon,
  description,
}: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="stat-icon">
        {icon}
      </div>

      <div>
        <p className="stat-title">{title}</p>
        <h2>{value}</h2>

        {description && (
          <p className="stat-description">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}