"use client";

import Link from "next/link";
import { Button } from "./ui/button";
import Logo from "./ui/Logo";
import { usePathname } from "next/navigation";
import { IoIosMenu } from "react-icons/io";
import { useEffect, useState } from "react";
import { IoClose } from "react-icons/io5";

export interface NavigationItem {
  label: string;
  href: string;
}

export const navigationData: NavigationItem[] = [
  { label: "Home", href: "/" },
  { label: "Sign up", href: "/login?mode=signup" },
];

const Navigation = () => {
  const path = usePathname();
  const [showMenu, setShowMenu] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    setIsLoaded(true);
  }, []);

  return (
    <div
      className={`text-(--foreground) bg-(--background) border-b border-neutral-600 sticky top-0 z-50 shadow-nav transition-all duration-500 ease-in-out
                  ${isLoaded
          ? "translate-y-0 opacity-100"
          : "-translate-y-full opacity-0"
        }`}
    >
      <nav
        className={`flex py-6! items-center justify-between container relative z-20
                transition-all duration-300 ease-in-out`}
      >
        <Logo />

        {/* Desktop Menu */}
        <div className="flex items-center gap-14">
          <ul className="hidden lg:flex gap-10">
            {navigationData.map((item) => (
              <li key={item.label}>
                <Link
                  href={item.href}
                  className={`uppercase ${path === item.href
                    ? "font-medium text-purple-400 transform-all duration-300 ease-in-out"
                    : "hover:font-medium transform-all duration-300 ease-in-out"
                    }
                `}
                >
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>

          <div className="flex items-center gap-4">
            <Link href="/login" className="max-lg:hidden">
              <Button
                size="lg"
                className="text-white hover:scale-105 active:scale-95"
              >
                Login
              </Button>
            </Link>

            <button
              className="lg:hidden z-30 relative"
              onClick={() => setShowMenu((prev) => !prev)}
            >
              {showMenu ? <IoClose size={32} /> : <IoIosMenu size={32} />}
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile Menu Dropdown */}
      <div
        className={`lg:hidden overflow-hidden transition-all duration-300 ease-in-out relative z-20
          ${showMenu ? "max-h-screen opacity-100" : "max-h-0 opacity-0"}`}
      >
        <ul className="flex flex-col gap-8 container py-8!">
          {navigationData.map((item) => (
            <li key={item.label}>
              <Link
                href={item.href}
                className={`${path === item.href
                  ? "font-extrabold text-purple-400 transform-all duration-300 ease-in-out"
                  : "hover:font-extrabold transform-all duration-300 ease-in-out"
                  }
                `}
                onClick={() => setShowMenu(false)}
              >
                {item.label}
              </Link>
            </li>
          ))}
          <li>
            <Link href="/login">
              <Button
                size="lg"
                variant="outline"
                className="w-full text-center hover:scale-105 active:scale-95"
                onClick={() => setShowMenu(false)}
              >
                Login
              </Button>
            </Link>
          </li>
        </ul>
      </div>

      {showMenu && (
        <div
          className="fixed inset-0 backdrop-blur-sm bg-neutral-900/20 z-10 lg:hidden"
          onClick={() => setShowMenu(false)}
        />
      )}
    </div>
  );
};
export default Navigation;
