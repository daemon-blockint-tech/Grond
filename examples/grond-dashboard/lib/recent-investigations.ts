export const RECENT_KEY = "grond-recent-investigations";

export type RecentItem = {
  id: string;
  label: string;
  target: string;
  ts: number;
};

export function loadRecent(): RecentItem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as RecentItem[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveRecent(items: RecentItem[]) {
  localStorage.setItem(RECENT_KEY, JSON.stringify(items.slice(0, 50)));
}
