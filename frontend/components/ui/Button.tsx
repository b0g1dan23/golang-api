import Link from "next/link";

export interface ButtonProps {
  children: React.ReactNode;
  href?: string;
  className?: string;
  variant?: "primary" | "secondary" | "gradient";
  type?: "button" | "submit" | "reset";
  onClick?: () => void;
}

const Button = ({
  children,
  href,
  variant = "primary",
  className,
  onClick,
  type = "button",
}: ButtonProps) => {
  if (href) {
    return (
      <Link
        href={href}
        onClick={onClick}
        className={`rounded-xl inline-block text-nowrap
                  py-[1.6rem]! px-12! uppercase font-bold text-[1.4rem]
                  ${variant === "primary"
            ? "bg-purple-400 text-(--background-color) hover:bg-purple-600 hover:text-white"
            : variant === "secondary"
              ? "bg-purple-900 text-white border border-purple-400/30"
              : "bg-linear-to-r from-purple-700 to-purple-400 border-linear text-white"
          }
                  hover:scale-105 active:scale-90
                  transition-all duration-300 ease-in-out
                  ${className ?? ""}`}
      >
        {children}
      </Link>
    );
  }

  return (
    <button
      onClick={onClick}
      type={type}
      className={`rounded-xl overflow-hidden inline-block text-nowrap
                  py-[1.6rem]! px-12! uppercase font-bold text-[1.4rem]
                  ${variant === "primary"
          ? "bg-purple-400 text-(--background-color) hover:bg-purple-600 hover:text-white"
          : variant === "secondary"
            ? "bg-purple-900 text-white border border-purple-400/30"
            : "bg-linear-to-r from-purple-700 to-purple-400 border-linear text-white"
        }
                  hover:scale-105 active:scale-90
                  cursor-pointer
                  transition-all duration-300 ease-in-out
                  ${className ?? ""}`}
    >
      {children}
    </button>
  );
};
export default Button;
