export default function Logo({ size = 24, className = '', style = {} }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={{ display: 'block', ...style }}
    >
      {/* Terminal Frame */}
      <rect
        x="6"
        y="8"
        width="44"
        height="38"
        rx="6"
        stroke="#10B981"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Terminal Prompt >_ */}
      <path
        d="M14 20L22 26L14 32"
        stroke="#10B981"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M27 32H35"
        stroke="#10B981"
        strokeWidth="4"
        strokeLinecap="round"
      />
      {/* Overlapping Shield in Bottom Right */}
      <path
        d="M38 32V42C38 49 48 56 48 56C48 56 58 49 58 42V32L48 28L38 32Z"
        fill="#0D0D0E"
        stroke="#10B981"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
