import login_photo from '@/public/login_photo.svg'
import Image from "next/image";
import { ReactNode } from 'react';

const layout = ({ children }: { children: ReactNode }) => {
    return (
        <>
            <div className="flex items-center justify-center h-screen">
                <div className="flex-1 max-lg:hidden">
                    <Image src={login_photo} alt="Login Photo" className="max-h-screen w-full" />
                </div>
                <div className="flex-1 flex flex-col justify-center items-center">
                    {children}
                </div>
            </div>
        </>
    )
}
export default layout