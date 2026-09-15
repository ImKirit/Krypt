// A small hand-drawn icon set on a 24px grid, stroked like the rest of the interface.

const PATHS: Record<string, string> = {
  lock: "M5.5 11h13v9.5h-13z M8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  search: "M10.5 17.5a7 7 0 1 1 0-14 7 7 0 0 1 0 14z M15.5 15.5l5 5",
  plus: "M12 5v14 M5 12h14",
  star: "M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.8l-5.2 2.8 1-5.8-4.3-4.1 5.9-.9z",
  trash: "M4.5 7h15 M9.5 7V4.5h5V7 M6.5 7l1 13h9l1-13",
  settings:
    "M12 15a3 3 0 1 1 0-6 3 3 0 0 1 0 6z M12 3v2.5 M12 18.5V21 M3 12h2.5 M18.5 12H21 M5.6 5.6l1.8 1.8 M16.6 16.6l1.8 1.8 M5.6 18.4l1.8-1.8 M16.6 7.4l1.8-1.8",
  copy: "M9 9h11v11H9z M5.5 15H4V4h11v1.5",
  eye: "M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12z M12 14.5a2.5 2.5 0 1 1 0-5 2.5 2.5 0 0 1 0 5z",
  eyeOff:
    "M3.5 3.5l17 17 M10 5.8a9.6 9.6 0 0 1 2-.3c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-2.8 3.6 M6.5 6.9C3.9 8.6 2.5 12 2.5 12s3.5 6.5 9.5 6.5c1.6 0 3-.4 4.3-1.1",
  edit: "M4 20h4.5L19.5 9 15 4.5 4 15.5z M13 6.5l4.5 4.5",
  restore: "M4.5 12a7.5 7.5 0 1 0 2.2-5.3 M4.5 4.5v4h4",
  x: "M6 6l12 12 M18 6L6 18",
  check: "M5 12.5l4.5 4.5L19 7.5",
  globe:
    "M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z M3 12h18 M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9 M12 3C9.6 5.5 8.4 8.5 8.4 12s1.2 6.5 3.6 9",
  layers: "M12 3.5l8.5 4.5-8.5 4.5L3.5 8z M3.5 12.5l8.5 4.5 8.5-4.5 M3.5 16.5l8.5 4.5 8.5-4.5",
  login: "M12 12a4 4 0 1 1 0-8 4 4 0 0 1 0 8z M4.5 20.5c1.2-3.5 4-5.5 7.5-5.5s6.3 2 7.5 5.5",
  api_key: "M8 16.5a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9z M12.5 12h8 M17.5 12v3.5 M20.5 12v2.5",
  passkey:
    "M12 11.5v3.5 M8.8 18c.8-1.6 1-3.3 1-5.5a2.2 2.2 0 0 1 4.4 0c0 1.9-.2 3.5-.7 5 M5.8 15.5c.3-1 .5-2 .5-3a5.7 5.7 0 0 1 11.4 0c0 1.5-.1 2.9-.5 4.2",
  totp: "M12 21a8 8 0 1 1 0-16 8 8 0 0 1 0 16z M12 9v4l2.5 2 M9.5 2.5h5",
  note: "M6 3.5h8.5L19 8v12.5H6z M14 3.5v5h5 M9 13h7 M9 16.5h5",
  recovery_codes: "M9 6h10.5 M9 12h10.5 M9 18h10.5 M4.5 6h.01 M4.5 12h.01 M4.5 18h.01",
  card: "M3 6h18v12H3z M3 10h18 M6.5 15h4",
  identity:
    "M3 5.5h18v13H3z M8.5 12a2 2 0 1 1 0-4 2 2 0 0 1 0 4z M5.5 16c.6-1.5 1.6-2.3 3-2.3s2.4.8 3 2.3 M14 9.5h4.5 M14 13h4.5",
  ssh_key: "M3.5 5h17v14h-17z M7 9.5l3 2.5-3 2.5 M12.5 15h4.5",
  env_file: "M6 3.5h8.5L19 8v12.5H6z M14 3.5v5h5 M9 12.5h1.5 M9 16h1.5 M12.5 12.5h3.5 M12.5 16h3.5",
  database:
    "M12 8c4.1 0 7.5-1.2 7.5-2.8S16.1 2.5 12 2.5 4.5 3.7 4.5 5.2 7.9 8 12 8z M4.5 5.2v13.6c0 1.5 3.4 2.7 7.5 2.7s7.5-1.2 7.5-2.7V5.2 M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8",
  chevron: "M9 6l6 6-6 6",
  warning: "M12 3.5l9.5 16.5h-19z M12 10v4.5 M12 17.5h.01",
};

export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={PATHS[name] ?? PATHS.note} />
    </svg>
  );
}

export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg className="logo-mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect x="1" y="1" width="30" height="30" rx="8" fill="currentColor" />
      <circle cx="16" cy="13.2" r="3.7" fill="var(--bg)" />
      <path d="M14.1 15.6h3.8l1.2 8.1h-6.2z" fill="var(--bg)" />
    </svg>
  );
}
