import { cn } from "@/lib/utils";

export function GrondLogo({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-7 max-h-7 w-full max-w-[8.5rem] min-w-0 shrink-0 items-center",
        className,
      )}
    >
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/grond-logo-black.svg"
        alt="Grond"
        width={120}
        height={36}
        className="h-7 max-h-7 w-full max-w-full object-contain object-left dark:hidden"
      />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/grond-logo-white.svg"
        alt="Grond"
        width={120}
        height={36}
        className="hidden h-7 max-h-7 w-full max-w-full object-contain object-left dark:block"
      />
    </span>
  );
}
